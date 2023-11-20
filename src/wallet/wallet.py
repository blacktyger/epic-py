from _decimal import Decimal
import subprocess
import datetime
import asyncio
import signal
import json
import os

import psutil

from .http_api import HttpServer
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
    DECIMALS = Decimal(10 ** 8)

    def __init__(self, path: str = None, logger=None, long_running: bool = False):
        if logger is None:
            logger = utils.logger

        self.logger = logger
        self.updating = False
        self._long_running = long_running

        if path:
            self.load_from_path(path)

    @property
    def long_running(self):
        return self._long_running

    @long_running.setter
    def long_running(self, value):
        self._long_running = value
        self.api_http_server.long_running = value

    async def create_new(self, **kwargs):
        # Make sure all the required arguments are provided
        REQUIRED = ('binary_file_path', 'password')

        if not all(arg in kwargs for arg in REQUIRED):
            raise Exception(f'Missing required argument/s, provide all: {REQUIRED}') from None

        # Get models.Config fields from kwargs
        config_ = dict()

        for k, v in kwargs.items():
            if k in models.Config.__fields__.keys():
                config_[k] = v

        self.config = models.Config(**config_)

        # Make sure binary wallet-cli file exists
        if not os.path.isfile(self.config.binary_file_path):
            raise Exception(f'Invalid wallet-cli {self.config.binary_file_path} binary file path') from None

        # Create new top_dir wallet directory
        try:
            os.makedirs(self.config.wallet_data_directory)
        except FileExistsError:
            try:
                data = self.load_from_path(self.config.wallet_data_directory)
            except Exception as e:
                self.logger.warning(f"Can't load wallet from path {self.config.wallet_data_directory}: {str(e)}")
                data = None

            return {'error': 1, 'msg': "Wallet already exists", 'data': data}

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
        settings_file = f"{os.path.join(self.config.wallet_data_directory, utils.defaults.BINARY_NAME)}.toml"
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

        # Save password to storage and store only reference to it
        self.config.password = utils.secrets.set(value=self.config.password, path=self.config.wallet_data_directory)
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
        self.logger.info(f'[WALLET_INST]: Load wallet from path: {path}')
        config_file = os.path.join(path, "config.toml")
        self.config = models.Config.from_toml(config_file)

        settings_file = f"{os.path.join(self.config.wallet_data_directory, utils.defaults.BINARY_NAME)}.toml"
        self.settings = models.Settings(file_path=settings_file)

        self.api_http_server = HttpServer(self.settings, self.config, self.long_running)

        return self

    async def _get_height(self, provider: HttpServer = None) -> int:
        if provider is None:
            async with self.api_http_server as provider:
                h = await provider.node_height()
                return int(h['height'])
        else:
            h = await provider.node_height()
            return int(h['height'])

    def _readable_ints(self, value: int | str) -> Decimal:
        """Parse big int numbers and return human-readable float/int values"""
        value = Decimal(value)
        return value / self.DECIMALS

    async def run_epicbox(self, callback=None, force_run: bool = False, logger=None,
                          close_after_tx: bool = False) -> models.Listener | None:
        running_listener: models.Listener | None = None

        for listener in self.api_http_server.listeners:
            if listener.method == 'epicbox' and listener.process:
                running_listener = listener

        if running_listener:
            self.logger.critical(f"Epicbox listener already running, PID: {running_listener.process.pid}")

            if force_run:
                running_listener.stop()
                self.logger.debug(f"Epicbox listener process closed")
            else:
                return running_listener

        kwargs = dict(method="epicbox", callback=callback, logger=logger, close_after_tx=close_after_tx)
        return await self.api_http_server.run_server(**kwargs)

    def get_version(self) -> str:
        """Get epic-wallet cli version"""
        version = subprocess.check_output([f"{self.config.binary_file_path}", '--version'])
        version = version.decode().strip('\n').split(' ')[-1]
        return version

    def send_via_cli(self, amount: float | int, method: str, address: str = None, outputs: int = 1, confirmations: int = 1,
                     selection_strategy: str = 'smallest') -> dict:
        """
        Send transaction using command line
        :param amount: float|int, transaction value
        :param method: str, transaction method (epicbox, file, self, emoji
        :param address: str, address where to send
        :param outputs: int, number of change outputs to create
        :param confirmations: int, number of confirmations needed to confirm transaction
        :param selection_strategy: str, either to use all outputs (mix) or minimum required, possible ['smallest', 'all']
        """

        address = f'-d {address} ' if address else ''
        password = utils.secrets.get(self.config.password)
        arguments = f'{self.config.binary_file_path} -p {password} -t {self.config.wallet_data_directory} -c {self.config.wallet_data_directory} ' \
                    f'send -m {method} {address}{amount} -c {confirmations} -o {outputs} -s {selection_strategy}'
        try:
            process = subprocess.Popen(arguments.split(' '), text=True)
            return {'error': False, 'msg': f'tx sent successfully', 'data': process.stdout}

        except Exception as e:
            return {'error': True, 'msg': f'{str(e)}', 'data': None}

    async def _start_updater(self, callback=None, interval: int = 5, timeout: int = 3*60):
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

        # If latest cached balance is not older than given tolerance (in seconds) don't refresh
        if self._cached_balance:
            if datetime.datetime.now() < self._cached_balance.timestamp + datetime.timedelta(seconds=cached_time_tolerance):
                return self._cached_balance

        self.updating = True
        try:
            async with self.api_http_server as provider:
                # Get the wallet balance
                balance_ = await provider.retrieve_summary_info()
                self._cached_balance = models.Balance(**balance_)

                if get_outputs:
                    # Get the wallet unspent outputs quantity
                    outputs = await provider.retrieve_outputs(refresh=False)
                    self._cached_balance.outputs = outputs

        except Exception as e:
            self.logger.error(f"epic::wallet::get_balance(): {str(e)}")
            self._cached_balance = models.Balance(error=str(e))
            self.updating = False
            return

        self.updating = False
        return self._cached_balance

    async def calculate_fees(self, amount: float | int | str, **kwargs) -> Decimal | None:
        """
        Calculate transaction fee for the given amount
        :param amount: float|int, transaction value
        """
        try:
            async with self.api_http_server as provider:
                response = await provider.get_fees(amount, **kwargs)
                return self._readable_ints(response)

        except Exception as e:
            utils.logger.error(str(e))
            return None

    async def create_outputs(self, num: int, **kwargs) -> dict:
        """
        Create extra _num_ outputs in the wallet, it will join all existing outputs in to single one before executing
        :param num: int, number of outputs to create, min: 2, max: 15
        """
        if not 1 < num <= 15:
            return {'error': True, 'msg': 'Wrong amount of outputs to create, min: 2, max: 15', 'data': None}

        try:
            balance = await self.get_balance(get_outputs=True, **kwargs)
            current_outputs = len(balance.outputs)
            if current_outputs + num > 100:
                return {'error': True, 'msg': f'Max outputs per wallet: 100, now: {current_outputs}', 'data': None}
        except Exception as e:
            return {'error': True, 'msg': f'{str(e)}', 'data': None}

        try:
            tx_value = Decimal(balance.total / Decimal(num + 1)).quantize(Decimal('.000001'))
            outputs_to_create = num - 1

            self.send_via_cli(amount=(float(tx_value)), method='self', outputs=outputs_to_create, selection_strategy='all')
            return {'error': False, 'msg': f'Outputs created successfully', 'data': {'outputs': num}}
        except Exception as e:
            return {'error': True, 'msg': f'{str(e)}', 'data': None}

    async def get_transactions(self, status: str = None, tx_type: str = None, tx_slate_id: str = None, refresh: bool = True) -> dict:
        """
        Get wallet local database transactions record
        :param tx_slate_id: str, transaction uuid
        :param tx_type: str, possible: 'sent', 'received'
        :param refresh: bool, whether refresh from node
        :param status: str, possible: 'confirmed', 'pending', 'failed', 'unknown'
        :return: dict with data as list of models.Transaction objects
        """
        try:
            async with self.api_http_server as provider:
                response = await provider.retrieve_txs(tx_slate_id=tx_slate_id, refresh=refresh)

                def filter_(tx):
                    return (status is None or tx.status.lower() == status) and (tx_type is None or tx_type in tx.tx_type.lower())

                if status or tx_type:
                    response = filter(lambda tx: filter_(tx), response)

                return {'error': False, 'msg': 'Transaction history success', 'data': list(response)}

        except Exception as e:
            return {'error': True, 'msg': f'{str(e)}', 'data': None}

    async def cancel_transaction(self, tx_slate_id: str = None) -> dict:
        """
        Cancel transaction in local wallet database
        :param tx_slate_id: str, transaction uuid
        :return: dict
        """
        try:
            async with self.api_http_server as provider:
                await provider.cancel_tx(tx_slate_id=tx_slate_id)
                return {'error': False, 'msg': 'Transaction cancelled', 'data': tx_slate_id}

        except Exception as e:
            return {'error': True, 'msg': f'{str(e)}', 'data': None}

    async def send_epicbox_tx(self, amount: float | int | str, address: str, **kwargs) -> dict:
        """
        Send EPIC transaction vit epicbox method
        :param amount: int | float, transaction amount
        :param address: str, receiver epicbox address
        """

        try:
            async with self.api_http_server as provider:
                response = await provider.send_via_epicbox(address=address, amount=amount, **kwargs)
                utils.logger.info(f"[WALLET_INST]: transaction sent successfully")
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
        utils.logger.debug(response_tx_file)
        with open(response_tx_file, 'r') as file:
            tx_response_slate = json.loads(file.read())

        async with self.api_http_server as provider:
            finalize_slate = provider.finalize_tx(slate=tx_response_slate)
            provider.post_tx(tx=finalize_slate['tx'])
            return True

    def epicbox_logger(self, line: str):
        tx_slate_id = utils.parse_uuid(line)
        if tx_slate_id and 'wallet_' not in line:
            utils.logger.critical(f"[EPICBOX_LOG] [{self.config.name}]: {line}")

            if 'Starting to send slate' in line:
                for listener in self.api_http_server.listeners:
                    if listener.method == 'epicbox' and listener.close_after_tx:
                        asyncio.run(asyncio.sleep(2))
                        listener.stop()

    async def close_wallet(self, close_epicbox: bool = False) -> None:
        async with self.api_http_server as provider:
            await provider._close_wallet(close_epicbox)

    async def stop_listeners(self) -> None:
        for listener in self.api_http_server.listeners:
            listener.stop()

        self.api_http_server._unlock()

    def __str__(self):
        return f"EpicWallet({self.config.name})"

    def __repr__(self):
        return f"EpicWallet({self.config.name})"
