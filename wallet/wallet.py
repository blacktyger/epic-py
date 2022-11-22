from typing import Union

from .key_manager import KeyManager
from .epicbox import EpicBoxHandler
from .http import HTTPHandler
from .cli import CLIHandler
from epicpy import utils
from . import models


class Wallet(HTTPHandler, CLIHandler, KeyManager, EpicBoxHandler):
    """
    Main class to manage Epic-Cash cli wallet through different methods
    :param wallet_dir: str, REQUIRED,  path to the top level wallet directory
           default '~/.epic/main/' or '%USERPROFILE%/.epic/main/'. Wallet will
           look for `wallet_data` dir with `wallet.seed` file inside
    """

    def __init__(self, wallet_dir: str, password: str, *args, **kwargs):
        self.wallet_dir = wallet_dir
        self.password = password
        self.config: models.WalletConfig

        for key, value in kwargs.items():
            setattr(self, key, value)

        CLIHandler.__init__(self, self.wallet_dir, self.password)
        KeyManager.__init__(self, *args, **kwargs)
        EpicBoxHandler.__init__(self, self.config)
        HTTPHandler.__init__(self,
            api_secret_path=self.config.wallet['api_secret_path'],
            api_interface=self.config.wallet['api_listen_interface'],
            foreign_port=self.config.wallet['api_listen_port'],
            owner_port=self.config.wallet['owner_api_listen_port'],
            password=self.password)

        print(f">> Epic-Cash wallet successfully initialized.")

    def open(self, password: str = None):
        """
        Start secure encrypted connection to the wallet's owner API
        and generate token used for the further communication
        :param password: str, wallet password
        """
        if not password: password = self.password

        self._init_secure_api()
        self._open_wallet(password)

        if self._encryption_key and self._token:
            utils.logger.info('Wallet initialized with owner access.')
        else:
            utils.logger.warning('Failed to open wallet.')

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
