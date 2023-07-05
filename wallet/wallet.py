import asyncio
import subprocess
import datetime
import decimal
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

    def __init__(self, path: str = None, logger=None):
        if logger is None:
            logger = utils.logger

        self.logger = logger
        self.updating = False
        if path:
            self.load_from_path(path)

    @utils.benchmark
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
            # Get wallet accounts (usually just one, 'default') and load to the Account object
            for i, acc in enumerate(provider.accounts()):
                self.accounts.append(models.Account(id=i, **acc))

            # Get the epic-box address
            public_key = provider.get_public_address()['public_key']
            self.config.epicbox = models.EpicBoxConfig(
                address=public_key, domain=self.settings.epicbox['epicbox_domain'],
                index=self.settings.epicbox['epicbox_address_index'], port=self.settings.epicbox['epicbox_port'])
            self.config.to_toml()

        return self

    def load_from_path(self, path: str):
        # Load created by wallet settings file to WalletTOML model
        config_file = os.path.join(path, "config.toml")
        self.config = models.Config.from_toml(config_file)

        settings_file = f"{os.path.join(self.config.wallet_data_directory, defaults.BINARY_NAME)}.toml"
        self.settings = models.Settings(file_path=settings_file)

        self.api_http_server = HttpServer(self.settings, self.config)

        return self

    async def run_epicbox(self, callback=None, force_run=False, logger=None) -> models.Listener | None:
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
        version = subprocess.check_output([f"{self.config.binary_file_path}", '--version'])
        version = version.decode().strip('\n').split(' ')[-1]
        return version

    async def _start_updater(self, callback=None):
        listener = await self.run_epicbox()

        async with self.api_http_server as provider:
            txs_before = len(await provider.retrieve_txs())
            start_time = datetime.datetime.now()
            self.updating = True

            while self.updating and datetime.datetime.now() - start_time < datetime.timedelta(seconds=3*60):
                updated_txs = await provider.retrieve_txs()

                if len(updated_txs) > txs_before:
                    num_of_new_txs = len(updated_txs) - txs_before
                    self.logger.critical(f"New tx ({num_of_new_txs}): {updated_txs[-num_of_new_txs:]}")
                    txs_before += num_of_new_txs

                    if callback:
                        await callback(updated_txs[-num_of_new_txs:])

                self.logger.debug(f"No new transactions")
                await asyncio.sleep(10)

            listener.stop()
        try:
            return updated_txs[-num_of_new_txs:]
        except UnboundLocalError:
            return []

    async def get_balance(self, cached_time_tolerance: int = 10) -> models.Balance:
        delta = datetime.datetime.now() + datetime.timedelta(seconds=cached_time_tolerance)

        # If latest cached balance is older than given tolerance (in seconds) refresh it from the node
        if not self._cached_balance or self._cached_balance.timestamp > delta:
            async with self.api_http_server as provider:
                self._cached_balance = models.Balance(**provider.retrieve_summary_info())

        return self._cached_balance

    async def is_balance_enough(self, amount: float | str | int, fee: float | str | int = None)-> tuple:
        balance = await self.get_balance()
        if not fee:
            fee = 0.008

        fee = decimal.Decimal(str(fee))
        amount = decimal.Decimal(str(amount))

        if balance.currently_spendable > (amount + fee):
            return True, balance
        else:
            return False, balance

    async def send_epicbox_tx(self, amount: float | int, address: str, **kwargs)-> dict:
        """
        Send EPIC transaction epicbox method
        :param amount: int | float, transaction amount
        :param address: str, receiver epicbox address
        """

        try:
            async with self.api_http_server as provider:
                response = await provider.send_via_epicbox(address=address, amount=amount, **kwargs)
                return {'error': False, 'msg': 'Transaction sent successfully', 'data': response}

        except Exception as e:
            return {'error': True, 'msg': f'{str(e)}', 'data': None}

    async def send_file_tx(self, amount: int | float | str, **kwargs)-> dict:
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

    async def receive_file_tx(self, init_tx_file: str, response_tx_file: str)-> dict:
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

    async def finalize_file_tx(self, response_tx_file: str)-> bool:
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

    def __str__(self):
        return f"EpicWallet(wallet_dir='{self.config.name}')"
