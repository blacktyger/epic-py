from typing import Union

from .key_manager import KeyManager
from .epicbox import EpicBoxHandler
from .http import HTTPHandler
from .cli import CLIHandler
from .. import utils
from . import models


class Wallet(HTTPHandler, CLIHandler, KeyManager, EpicBoxHandler):
    """
    Main class to manage Epic-Cash cli wallet through different methods
    :param wallet_dir: str, REQUIRED,  path to the top level wallet directory
           default '~/.epic/main/' or '%USERPROFILE%/.epic/main/'. Wallet will
           look for `wallet_data` dir with `wallet.seed` file inside
    """

    def __init__(self, wallet_dir: str, password: str, **kwargs):
        self.config = models.WalletConfig(wallet_dir, password, **kwargs)
        self.state = None
        self.is_locked = False

        KeyManager.__init__(self, **kwargs)

        if self.config:
            EpicBoxHandler.__init__(self, self.config)
            HTTPHandler.__init__(self, self.config)
            CLIHandler.__init__(self, self.config)

        print(f">> Epic-Cash wallet successfully initialized.")

    def load_config(self, wallet_dir: str, password: str):
        """load wallet config from *.toml file"""
        self.config = models.WalletConfig(wallet_dir, password)

    def open(self, password: str = None):
        """
        Start secure encrypted connection to the wallet's owner API
        and generate token used for the further communication
        :param password: str, wallet password
        """
        if not password: password = self.config.password

        self._init_secure_api()
        self._open_wallet(password)

        if self._encryption_key and self._token:
            utils.logger.info('Wallet initialized with owner access.')
        else:
            utils.logger.warning('Failed to open wallet.')

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
            return False

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
        return f"EpicWallet(wallet_dir='{self.wallet_dir}')"
