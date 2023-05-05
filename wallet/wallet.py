import datetime
import decimal
import shutil
import signal

from .http import HttpServer
from . import models
from ..utils import *


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

    def __init__(self, path: str = None):
        if path: self.load_from_path(path)

    @return_to_cwd
    @benchmark
    def create_new(self, **kwargs):
        # Make sure all the required arguments are provided
        REQUIRED = ('binary_path', 'password')

        if not all(arg in kwargs for arg in REQUIRED):
            raise SystemExit(f'Missing required argument/s, provide all: {REQUIRED}') from None

        self.config = models.Config(**kwargs)
        source_full_path = os.path.join(self.config.binary_path, self.config.binary_name)

        # Make sure source wallet-cli file exists
        if not os.path.isfile(source_full_path):
            raise SystemExit(f'Invalid wallet-cli {source_full_path} binary file path') from None

        # Create new top_dir wallet directory and copy source binary there
        os.makedirs(self.config.wallet_data_directory, exist_ok=True)
        shutil.copy(source_full_path, self.config.wallet_data_directory)
        os.chdir(self.config.wallet_data_directory)

        # Build full wallet init command string
        args = f"./{self.config.binary_name} -r {self.config.node_address} -p {self.config.password} init -h"

        # Execute that command to create new wallet and its initialize data
        subprocess.Popen(args.split(' ')).wait()

        # Load created by wallet settings file to WalletTOML model
        settings_file = f"{os.path.join(self.config.wallet_data_directory, self.config.binary_name)}.toml"
        self.settings = models.Settings(file_path=settings_file)
        self.api_http_server = HttpServer(self.settings, self.config)

        # Update / override default wallet settings
        if self.config.node_address:
            self.settings.set(category='wallet', key='check_node_api_http_addr', value=self.config.node_address)

        if self.config.epicbox_address:
            self.settings.set(category='epicbox', key='epicbox_domain', value=self.config.epicbox_address)

        if 'debug' in kwargs and kwargs['debug']:
            self.settings.set(category='logging', key='stdout_log_level', value="DEBUG")
            self.settings.set(category='logging', key='file_log_level', value="DEBUG")

        # Save password to secure storage with pass manager and store only reference to it
        secrets.set(f"{defaults.PASSWORD_STORAGE_PATH}/{self.config.id}", value=self.config.password)
        self.config.password = f"{defaults.PASSWORD_STORAGE_PATH}/{self.config.id}"
        self.config.to_toml()

        # Use HTTP API (owner and foreign) as context manager,
        # api calls are encrypted with token created only for current session
        with self.api_http_server as provider:
            # Get wallet accounts (usually just one, 'default') and load to the Account object
            for i, acc in enumerate(provider.accounts()):
                self.accounts.append(models.Account(id=i, **acc))
            print(self.accounts)

        # Get wallet balances
        self._cached_balance = self.get_balance()

        return self

    def load_from_path(self, path: str):
        # Load created by wallet settings file to WalletTOML model
        file = os.path.join(path, "config.toml")
        self.config = models.Config.from_toml(file)
        settings_file = f"{os.path.join(self.config.wallet_data_directory, self.config.binary_name)}.toml"
        self.settings = models.Settings(file_path=settings_file)
        self.api_http_server = HttpServer(self.settings, self.config)

        return self

    def run_epicbox(self, callback=None, force_run=False):
        already_running = find_process_by_name('method epicbox')

        if already_running:
            logger.critical(f"Epicbox listener already running, PID: {already_running}")

            if force_run:
                os.kill(already_running[0], signal.SIGKILL)
                logger.debug(f"Epicbox listener process closed")
            else:
                return

        with self.api_http_server as provider:
            provider._run_server(method="epicbox", callback=callback)

    @return_to_cwd
    def get_version(self):
        os.chdir(self.config.wallet_data_directory)
        version = subprocess.check_output([f"./{self.config.binary_name}", '--version'])
        version = version.decode().strip('\n').split(' ')[-1]
        return version

    def get_balance(self, cached_time_tolerance: int = 10):
        delta = datetime.datetime.now() + datetime.timedelta(seconds=cached_time_tolerance)

        # If latest cached balance is older than given
        # tolerance (in seconds) refresh it from the node
        if not self._cached_balance or self._cached_balance.timestamp > delta:
            with self.api_http_server as provider:
                self._cached_balance = models.Balance(**provider.retrieve_summary_info())

        return self._cached_balance

    def is_balance_enough(self, amount: float | str | int, fee: float = None):
        balance = self.get_balance()
        if not fee: fee = 0.008

        fee = decimal.Decimal(fee)
        amount = decimal.Decimal(amount)

        if balance.currently_spendable > (amount + fee):
            return True, balance
        else:
            return False, balance

    def send_transaction(self, method: str, amount: Union[float, int],
                         address: str, **kwargs):
        """
        Helper function to organize sending workflow
        :param method: str, transaction method (http, epicbox)
        :param amount: int | float, transaction amount
        :param address: str, receiver address
        """

        if method == 'epicbox':
            with self.api_http_server as provider:
                res = response(False, 'init_slate sent',
                               provider.send_via_epicbox(address=address, amount=amount, **kwargs))
        else:
            res = response(True, f"'{method}' method not supported, use 'http' or 'epicbox'")

        return res

    def __str__(self):
        return f"EpicWallet(wallet_dir='{self.config.wallet_data_directory}')"
