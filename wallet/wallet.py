import shutil
import time

from .http import HttpServer
from . import models
from utils import *


class Wallet:
    """
    Main class to manage Epic-Cash cli wallet through different methods
    :param wallet_dir: str, REQUIRED,  path to the top level wallet directory
           default '~/.epic/main/' or '%USERPROFILE%/.epic/main/'. Wallet will
           look for `wallet_data` dir with `wallet.seed` file inside
    """
    config: models.Config
    settings: models.Settings
    accounts: list[models.Account] = []
    cached_balance: models.Balance
    api_http_server: HttpServer

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

        # Build full wallet init command
        args = f"./{self.config.binary_name} -r {self.config.node_address} -p {self.config.password} init -h"

        # Create new wallet and its init data
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
        self.config = self.config.from_toml('config.toml')
        # Use HTTP API (owner and foreign) as context manager,
        # api calls are encrypted with token created only for current session
        with self.api_http_server as provider:

            # Get wallet accounts (usually just one, 'default') and load to the Account object
            for i, acc in enumerate(provider.accounts()):
                self.accounts.append(models.Account(id=i, **acc))
            print(self.accounts)

            # Get wallet balances
            self.cached_balance = models.Balance(**provider.retrieve_summary_info())
            print(self.cached_balance)

        return self

    @return_to_cwd
    def get_version(self):
        os.chdir(self.config.wallet_data_directory)
        version = subprocess.check_output(['./epic-wallet',  '--version'])
        version = version.decode().strip('\n').split(' ')[-1]
        return version

    def get_balance(self):
        self.open()
        balance = self.retrieve_summary_info()
        self.close()
        return balance

    def is_balance_enough(self, amount: float | str | int):
        balance = self.get_balance()
        fee = 0.008
        if float(balance['amount_currently_spendable']) > (float(amount) + fee):
            return balance
        else:
            return None

    def send_transaction(self, method: str, amount: Union[float, int],
                         address: str, **kwargs):
        """
        Helper function to organize sending workflow
        :param method: str, transaction method (http, epicbox)
        :param amount: int | float, transaction amount
        :param address: str, receiver address
        """

        if method == 'http':
            self._send_via_http(addres=address, amount=amount, **kwargs)
        elif method == 'epicbox':
            self._send_via_epicbox(addres=address, amount=amount, **kwargs)
        else:
            raise SystemExit(f"'{method}' method not supported, use 'http' or 'epicbox'")

    def __str__(self):
        return f"EpicWallet(wallet_dir='{self.config.wallet_dir}')"
