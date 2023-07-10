import subprocess
import datetime
import decimal
import asyncio
import signal
import json
import os

from .http import HttpServer
from ..utils import defaults
from . import models
from .. import utils


class Wallet:
    """
    Main class to manage EPIC Wallet through different methods
    """
    config: models.Config
    settings: models.Settings
    accounts: list[models.Account] = []
    _cached_balance: models.Balance = None
    api_http_server: HttpServer
    state: object = None
    DECIMALS = 10 ** 8

    def __init__(self, path: str = None, logger=None):
        if logger is None:
            logger = utils.logger

        self.logger = logger
        self.updating = False
        if path:
            self.load_from_path(path)

    async def create_new(self, **kwargs):
        # Make sure all the required arguments are provided
        REQUIRED = ('binary_file_path', 'password')

        if not all(arg in kwargs for arg in REQUIRED):
            raise SystemExit(f'Missing required argument/s, provide all: {REQUIRED}') from None

        # Get models.Config fields from kwargs
        config_ = dict()

        for k, v in kwargs.items():
            if k in models.Config.__fields__.keys():
                config_[k] = v

        self.config = models.Config(**config_)

        # Make sure binary wallet-cli file exists
        if not os.path.isfile(self.config.binary_file_path):
            raise SystemExit(f'Invalid wallet-cli {self.config.binary_file_path} binary file path') from None

        # Create new top_dir wallet directory
        try:
            os.makedirs(self.config.wallet_data_directory)
        except FileExistsError:
            return {'error': 1, 'msg': "Wallet already exists", 'data': None}

        # Create directory to store transaction files
        self.config.tx_files_directory = os.path.join(self.config.wallet_data_directory, 'tx_files')
        self.config.lock_file = os.path.join(self.config.wallet_data_directory, '.lock')

        os.makedirs(self.config.tx_files_directory)

        # Build full wallet init command string
        args = f"{self.config.binary_file_path} -r {self.config.node_address} -p {self.config.password} " \
               f"-t {self.config.wallet_data_directory} -c {self.config.wallet_data_directory} init"

        # Execute that command to create new wallet and its initialize data
        subprocess.Popen(args.split(' ')).wait()

        # Load created by wallet settings file to WalletTOML model
        settings_file = f"{os.path.join(self.config.wallet_data_directory, defaults.BINARY_NAME)}.toml"
        self.settings = models.Settings(file_path=settings_file)
        self.api_http_server = HttpServer(self.settings, self.config)

        # Update / override default wallet settings
        self.settings.set(category='wallet', key='owner_api_include_foreign', value=True)

        if self.config.node_address:
            self.settings.set(category='wallet', key='check_node_api_http_addr', value=self.config.node_address)

        if 'owner_api_listen_port' in kwargs:
            self.settings.set(category='wallet', key='owner_api_listen_port', value=kwargs['owner_api_listen_port'])

        if 'epicbox_domain' in kwargs:
            self.settings.set(category='epicbox', key='epicbox_domain', value=kwargs['epicbox_domain'])

        if 'debug' in kwargs and kwargs['debug']:
            self.settings.set(category='logging', key='stdout_log_level', value="DEBUG")
            self.settings.set(category='logging', key='file_log_level', value="DEBUG")

        # Save password to secure storage with pass manager and store only reference to it
        utils.secrets.set(f"{utils.defaults.PASSWORD_STORAGE_PATH}/{self.config.id}", value=self.config.password)
        self.config.password = f"{utils.defaults.PASSWORD_STORAGE_PATH}/{self.config.id}"
        self.config.to_toml()

        # Use HTTP API (owner and foreign) as context manager,
        # api calls are encrypted with token created only for current session
        async with self.api_http_server as provider:
            # Get blockchain height when wallet was created
            self.config.created_at_height = await self._get_height(provider)

            # Scan the wallet against the blockchain
            await provider.scan(start_height=self.config.created_at_height)

            # Get wallet accounts (usually just one, 'default') and load to the Account object
            for i, acc in enumerate(await provider.accounts()):
                self.accounts.append(models.Account(id=i, **acc))

            # Get the epic-box address
            pub_key_ = await provider.get_public_address()
            pub_key = pub_key_['public_key']
            self.config.epicbox = models.EpicBoxConfig(
                address=pub_key, domain=self.settings.epicbox['epicbox_domain'],
                index=self.settings.epicbox['epicbox_address_index'], port=self.settings.epicbox['epicbox_port'])
            self.config.to_toml()

        return {'error': 0, 'msg': "wallet created", 'data': self}

    def load_from_path(self, path: str):
        # Load created by wallet settings file to WalletTOML model
        config_file = os.path.join(path, "config.toml")
        self.config = models.Config.from_toml(config_file)

        settings_file = f"{os.path.join(self.config.wallet_data_directory, defaults.BINARY_NAME)}.toml"
        self.settings = models.Settings(file_path=settings_file)

        self.api_http_server = HttpServer(self.settings, self.config)

        return self

    async def _get_height(self, provider: HttpServer = None) -> dict:
        if provider is None:
            async with self.api_http_server as provider:
                h = await provider.node_height()
                return h['height']
        else:
            h = await provider.node_height()
            return h['height']

    def _readable_ints(self, value: int | str) -> float | int:
        """Parse big int numbers and return human-readable float/int values"""
        if isinstance(value, str):
            value = int(value)

        return value / self.DECIMALS

    async def run_epicbox(self, callback=None, force_run: bool = False, ignore_duplicate_name: bool = True, logger=None) -> models.Listener | None:
        if not ignore_duplicate_name:
            already_running = utils.find_process_by_name('method epicbox')

            if already_running:
                self.logger.critical(f"Epicbox listener already running, PID: {already_running}")

                if force_run:
                    os.kill(already_running[0], signal.SIGKILL)
                    self.logger.debug(f"Epicbox listener process closed")
                else:
                    return

        await self.api_http_server.run_server(method="epicbox", callback=callback, logger=logger)

        return self.api_http_server.listeners[-1]

    def get_version(self) -> str:
        """Get epic-wallet cli version"""
        version = subprocess.check_output([f"{self.config.binary_file_path}", '--version'])
        version = version.decode().strip('\n').split(' ')[-1]
        return version

    def send_via_cli(self, amount: float | int, address: str, method: str, outputs: int = 1, confirmations: int = 1) -> str:
        """
        Send transaction using command line
        :param amount: float|int, transaction value
        :param address: str, address where to send
        :param method: str, transaction method (epicbox, file, self, emoji
        :param outputs: int, number of change outputs to create
        :param confirmations: int, number of confirmations needed to confirm transaction
        """
        password = utils.secrets.get(self.config.password)
        arguments = f'{self.config.binary_file_path} -p {password} -t {self.config.wallet_data_directory} -c {self.config.wallet_data_directory} ' \
                    f'send -m {method} -d {address} {amount} -c {confirmations} -o {outputs}'
        process = subprocess.Popen(arguments.split(' '), text=True)
        stdout, stderr = process.communicate()
        return stdout

    async def _start_updater(self, callback=None, interval: int = 10, timeout: int = 3*60):
        """
        Strat epicbox listener background process with transaction listener, terminate after first received transaction or timeout
        :param callback: callable, function executed when transaction is received
        :param interval: int, how often (in seconds) get new updates
        :param timeout: int, how long keep the listener process running before terminating
        """
        listener = await self.run_epicbox()

        async with self.api_http_server as provider:
            txs_before = len(await provider.retrieve_txs())
            start_time = datetime.datetime.now()

            while self.updating and datetime.datetime.now() - start_time < datetime.timedelta(seconds=timeout):
                updated_txs = await provider.retrieve_txs()

                if len(updated_txs) > txs_before:
                    num_of_new_txs = len(updated_txs) - txs_before
                    self.logger.critical(f"New tx ({num_of_new_txs}): {updated_txs[-num_of_new_txs:]}")
                    txs_before += num_of_new_txs

                    if callback:
                        await callback(updated_txs[-num_of_new_txs:])

                self.logger.debug(f"No new transactions")
                await asyncio.sleep(interval)

            listener.stop()
        try:
            return updated_txs[-num_of_new_txs:]
        except UnboundLocalError:
            return []

    async def get_balance(self, get_outputs: bool = False, cached_time_tolerance: int = 10) -> models.Balance | None:
        """
        Get epic-wallet balance
        :param get_outputs: bool, if true return number of available unspent outputs
        :param cached_time_tolerance: int, use previously cached balance if no older than this value (in seconds)
        """

        delta = datetime.datetime.now() + datetime.timedelta(seconds=cached_time_tolerance)

        # If latest cached balance is older than given tolerance (in seconds) refresh it from the node
        if not self._cached_balance or self._cached_balance.timestamp > delta:
            self.updating = True
            try:
                async with self.api_http_server as provider:
                    # Get the wallet balance
                    balance_ = await provider.retrieve_summary_info()
                    self._cached_balance = models.Balance(**balance_)

                    if get_outputs:
                        # Get the wallet unspent outputs quantity
                        outputs = await provider.retrieve_outputs(refresh=False)
                        self._cached_balance.outputs = len(outputs)

            except Exception as e:
                self.logger.error(f"epic::wallet::get_balance(): {str(e)}")
                self._cached_balance = models.Balance(error=str(e))
                self.updating = False
                return

        self.updating = False
        return self._cached_balance

    async def calculate_fees(self, amount: float | int, **kwargs) -> dict:
        """
        Calculate transaction fee for the given amount
        :param amount: float|int, transaction value
        """
        try:
            async with self.api_http_server as provider:
                response = await provider.get_fees(amount, **kwargs)
                return {'error': False, 'msg': 'get fee success', 'data': self._readable_ints(response)}

        except Exception as e:
            return {'error': True, 'msg': f'{str(e)}', 'data': None}

    async def is_balance_enough(self, amount: float | str | int, fee: float | str | int = None) -> tuple:
        """
        Check if wallet balance is enough to send given amount (including fees)
        :param amount: float|int, transaction value
        :param fee: float|str, fee value, optional

        """
        balance = await self.get_balance()

        if not fee:
            # Calculate the transaction fee
            with self.api_http_server as provider:
                fee = await provider.get_fee(amount)

        fee = decimal.Decimal(str(fee))
        amount = decimal.Decimal(str(amount))

        if balance.spendable > (amount + fee):
            return True, balance
        else:
            return False, balance

    async def send_epicbox_tx(self, amount: float | int, address: str, **kwargs) -> dict:
        """
        Send EPIC transaction vit epicbox method
        :param amount: int | float, transaction amount
        :param address: str, receiver epicbox address
        """

        try:
            async with self.api_http_server as provider:
                response = await provider.send_via_epicbox(address=address, amount=amount, **kwargs)
                return {'error': False, 'msg': 'Transaction sent successfully', 'data': response}

        except Exception as e:
            return {'error': True, 'msg': f'{str(e)}', 'data': None}

    async def send_file_tx(self, amount: int | float | str, **kwargs) -> dict:
        """
        Send EPIC transaction via transaction file method
        :param amount: int | float, transaction amount
        """
        amount = str(amount)

        try:
            async with self.api_http_server as provider:
                response = provider.send_via_file(amount=amount, **kwargs)
                return {'error': False, 'msg': 'Transaction sent successfully', 'data': response}

        except Exception as e:
            return {'error': True, 'msg': f'{str(e)}', 'data': None}

    async def receive_file_tx(self, init_tx_file: str, response_tx_file: str) -> dict:
        """
        Receive EPIC transaction via transaction file method
        :param init_tx_file: str, path of the init transaction file (input)
        :param response_tx_file: str, path of the response transaction file (output)
        """
        with open(init_tx_file, 'r') as file:
            tx_slate = json.loads(file.read())

        try:
            async with self.api_http_server as provider:
                response = provider.receive_tx(tx_slate=tx_slate)
                response_file_path = f"{response_tx_file}.response"

                with open(response_file_path, 'w') as file:
                    file.write(json.dumps(response))

                return {'error': False, 'msg': 'Transaction sent successfully', 'data': response_file_path}

        except Exception as e:
            return {'error': True, 'msg': f'{str(e)}', 'data': None}

    async def finalize_file_tx(self, response_tx_file: str) -> bool:
        """
        Finalize EPIC transaction via transaction file method
        :param response_tx_file: str, path of the response transaction file (input)
        """
        print(response_tx_file)
        with open(response_tx_file, 'r') as file:
            tx_response_slate = json.loads(file.read())

        async with self.api_http_server as provider:
            finalize_slate = provider.finalize_tx(slate=tx_response_slate)
            provider.post_tx(tx=finalize_slate['tx'])
            return True

    # def __str__(self):
    #     return f"EpicWallet(wallet_dir='{self.config.name}')"
