from typing import Union
import os

from .wallet_http import HTTPHandler
from .wallet_cli import KeyManager, CLIHandler
from epicpy.models import WalletConfig
from . import utils


class Wallet(HTTPHandler, CLIHandler, KeyManager):
    """
    Main class to manage Epic-Cash cli wallet through different methods
    :param wallet_dir: str, REQUIRED,  path to the top level wallet directory
           default '~/.epic/main/' or '%USERPROFILE%/.epic/main/'. Wallet will
           look for `wallet_data` dir with `wallet.seed` file inside
    """
    auth_user = 'epic'
    owner_api_version = 'v3'
    foreign_api_version = 'v2'

    def __init__(self, wallet_dir: str, *args, **kwargs):
        self.wallet_dir = wallet_dir
        self.config: WalletConfig

        for key, value in kwargs.items():
            setattr(self, key, value)

        CLIHandler.__init__(self, self.wallet_dir, *args, **kwargs)
        # KeyManager.__init__(self, *args, **kwargs)
        # HTTPHandler.__init__(self, **connector)

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
        Helper function to organize sending via HTTP/S workflow
        :param method: str, transaction method (http, file, tor)
        :param amount: int | float, transaction amount
        :param address: str, receiver address
        """

        # Prepare transaction slate with partial data
        transaction = self._prepare_slate(amount, **kwargs)
        tx = self.init_send_tx(transaction)
        print('>> preparing transaction (init_send_tx)')

        if method == 'http':
            address = f'{address}/{self.foreign_api_version}/foreign'
            # Lock sender's outputs for transaction
            print('>> locking funds (lock_outputs)')
            self.tx_lock_outputs(tx)

            try:
                # Connect to receiver's foreign api wallet and send transaction slate
                print('>> sending slate to receiver (receive_tx)')
                response_tx = self.send_to_receiver_via_http(address, tx)

                # Validate receiver's transaction response slate
                print('>> validate receiver response (finalize)')
                finalize = self.finalize_tx(response_tx)

                # Send transaction to network using connected node
                print('>> sending tx to network (post_tx)')
                post_tx = self.post_tx(finalize['tx'])

                if post_tx:
                    print(f'>> transaction sent successfully')
                    return finalize

            except Exception as e:
                print(e)
                print('>> transaction failed, delete:', self.cancel_tx(tx_slate_id=tx['id']))
                return
        else:
            raise SystemExit(f"'{method}' method not supported, use 'http' instead.")

    @staticmethod
    def parse_secret(secret: str) -> str:
        """
        Parse secret, input can be path to file or secret itself
        :param secret: string, path or secret
        :return: string, secret
        """
        if os.path.isfile(secret):
            with open(secret, 'r') as f:
                wallet_secret = f.read()
            return wallet_secret
        else:
            return secret

    def __str__(self):
        return f"EpicWallet(wallet_dir='{self.wallet_dir}')"
