import shutil

from .http import HttpAPIServer
from utils import *
from . import models


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
    listeners: list[models.Listener] = []

    class API:
        http: HttpAPIServer

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
        self.API.http = HttpAPIServer(settings=self.settings)

        # Update / override default wallet settings
        if self.config.node_address:
            self.settings.set(category='wallet', key='check_node_api_http_addr', value=self.config.node_address)

        if self.config.epicbox_address:
            self.settings.set(category='epicbox', key='epicbox_domain', value=self.config.epicbox_address)

        if 'debug' in kwargs and kwargs['debug']:
            self.settings.set(category='logging', key='stdout_log_level', value="DEBUG")
            self.settings.set(category='logging', key='file_log_level', value="DEBUG")

        # Save password to secure storage with pass manager and store in object only path
        self.config.password = secrets.set_value(f"{defaults.PASSWORD_STORAGE_PATH}/{self.config.id}",
                                                 value=self.config.password)

        # Run owner listener to access wallet HTTP API
        # for method in ['http', 'owner_api', 'epicbox']:
        listener_ = models.Listener(settings=self.settings, config=self.config, method='owner_api')
        self.listeners.append(listener_.run())
        print(self.listeners)
        print(self.open())
        print(self.API.html.accounts())

        listener_.stop()

        # # Add default account created with wallet initialization
        # self.accounts += models.Account()

        # Show wallet info
        # args = f'./{self.config.binary_name} info'
        # info_wallet = subprocess.Popen(args.split(' '), stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

        # # Provide pass as input, not argument (security)
        # print(info_wallet.communicate(
        #     input=get_secret_value(f"{defaults.PASSWORD_STORAGE_PATH}/{self.config.id}"))[0])

        return self

    def open(self):
        """
        Start secure encrypted connection to the wallet's owner API
        and generate token used for the further communication
        :param password: str, wallet password
        """

        self.API.http.init_secure_api()
        self.API.http.open_wallet(secrets.get_value(self.config.password))

        if self.API.http.encryption_key and self.API.http.token:
            logger.info('Wallet initialized with owner access.')
        else:
            logger.warning('Failed to open wallet.')

    def get_version(self):
        cwd = os.getcwd()
        os.chdir(self.config.wallet_dir)
        version = subprocess.check_output(['./epic-wallet',  '--version'])
        version = version.decode().strip('\n').split(' ')[-1]
        os.chdir(cwd)
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
