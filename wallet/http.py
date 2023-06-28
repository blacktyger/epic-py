from typing import Union
import base64
import json
import time
import os

from coincurve import PublicKey, PrivateKey
from Crypto.Cipher import AES
import requests

from .. import utils
from . import models

class HttpServer:
    """
    Can be used as context manager, it will take care of the background processes,
    wallet authorization, data encryption and proper exit handling.
    ```
        http_server = HttpServer(**kwargs)

        with http_server as provider:
            provider.retrieve_summary_info()
            ...
    ```
    """

    auth_user = 'epic'
    owner_api_version = 'v3'
    foreign_api_version = 'v2'
    listeners: list[models.Listener] = []

    def __init__(self, settings, config):
        self.settings = settings
        self.config = config
        self._token: str = ''
        self._secret: PrivateKey = PrivateKey(os.urandom(32))
        self._encryption_key: str = ''

        settings_ = self.settings.wallet
        self.foreign_api = f"http://{settings_['api_secret_path']}:{settings_['api_listen_port']}/" \
                           f"{self.foreign_api_version}/foreign",
        self.owner_api = f"http://{settings_['api_listen_interface']}:{settings_['owner_api_listen_port']}/" \
                         f"{self.owner_api_version}/owner",
        self.auth = (self.auth_user, self.parse_secret(settings_['api_secret_path']))

    def _secure_api_call(self, method: str, params: dict) -> dict:
        """
        Execute secure owner_api call, payload is encrypted
        :param method: api call method name
        :param params: dict with api_call params
        :return: dict with decrypted data
        """
        if not self._encryption_key:
            raise Exception('Need encryption key, call init_secure_api() first.')

        payload = {
            'jsonrpc': '2.0',
            'id': 1,
            'method': method,
            'params': params
            }

        # Encrypt payload with computed encryption key
        encrypted_payload = self._encrypt(payload)

        # Execute owner_api call with encrypted payload
        encrypted_response = self._api_call(method='encrypted_request_v3', params=encrypted_payload)

        # Decrypt response and return dict with response data
        nonce = bytes.fromhex(encrypted_response['nonce'])
        encrypted_response = encrypted_response['body_enc']
        decrypted_response = self._decrypt(encrypted_response, nonce)

        return utils.parse_api_response(json.loads(decrypted_response))

    def __enter__(self):
        try:
            self._run_server(method="owner_api")
            time.sleep(1)
            self._init_secure_api()
            return self._open_wallet()

        except Exception as e:
            utils.logger.error(f"{e}")

    def __exit__(self, *args):
        time.sleep(1)
        self._close_wallet()

    def _init_secure_api(self) -> None:
        """
        This is the first step in epic-wallet API workflow
        Initialize process of computing encryption_key to encrypt all future api_calls
        :return: None, save encryption key to instance variable
        """

        # POST your secret.public_key and receive new api_public_key
        response = self._api_call(
            method='init_secure_api',
            params={'ecdh_pubkey': self._secret.public_key.format().hex()}
            )

        # Parse received api_public_key from hex to bytes
        api_public_key = PublicKey(bytes.fromhex(response)).format()

        # Compute new encryption_key used for further encryption every api_call
        # in this session
        self._encryption_key = PublicKey(api_public_key).multiply(self._secret.secret)

        # format to hex and remove first 2 bits
        self._encryption_key = self._encryption_key.format().hex()[2:]

    def _open_wallet(self):
        """
        This is the second step in epic-wallet API workflow
        Make api_call to open_wallet instance, get authentication token and use it
        in all future api_calls for this wallet instance
        """

        params = {
            'name': 'default',
            'password': utils.secrets.get(self.config.password),
            # 'password': self.config.password,
            }
        self._token = self._secure_api_call('open_wallet', params)

        return self

    def _run_server(self, method: str, callback=None):
        """
        Run listener process
        """
        listener = models.Listener(settings=self.settings, config=self.config, method=method)
        self.listeners.append(listener.run(force_run=True, callback=callback))
        time.sleep(1)
        return self.listeners[-1]

    def _close_wallet(self):
        self.close()
        for listener in self.listeners:
            if listener.method != "epicbox":
                listener.stop()

    def send_via_epicbox(self, amount: Union[float, int], address: str, **kwargs):
        # Prepare transaction slate with partial data
        print('>> preparing transaction (init_send_tx)')

        kwargs["send_args"] = {
            "method": "epicbox",
            "dest": address,
            "finalize": True,
            "post_tx": True,
            "fluff": False
            }

        init_slate = self._prepare_slate(amount, **kwargs)

        try:
            transaction = self.init_send_tx(init_slate)
            return transaction

        except Exception as e:
            print(e)
            print('>> transaction failed, delete:', self.cancel_tx(tx_slate_id=init_slate['id']))

    def node_height(self):
        """Get block height from connected node"""
        params = {'token': self._token}
        resp = self._secure_api_call('node_height', params)
        return resp

    def retrieve_txs(self, tx_id: Union[str, int] = None, tx_slate_id: str = None, refresh: bool = True) -> dict:
        """Return wallet transaction history"""
        params = {
            'token': self._token,
            'tx_id': tx_id,
            'tx_slate_id': tx_slate_id,
            'refresh_from_node': refresh,
            }
        resp = self._secure_api_call('retrieve_txs', params)

        if refresh and not resp[0]:
            # We requested refresh but data was not successfully refreshed
            raise Exception(f"retrieve_outputs, failed to refresh data from the node")

        return resp[1]

    def retrieve_outputs(self, include_spent=False, tx_id=None, refresh=True):
        """
        Returns a list of outputs from the active account in the wallet.
        """
        params = {
            'token': self._token,
            'include_spent': include_spent,
            'refresh_from_node': refresh,
            'tx_id': tx_id,
            }
        resp = self._secure_api_call('retrieve_outputs', params)
        if refresh and not resp[0]:
            # We requested refresh but data was not successfully refreshed
            raise Exception(f"retrieve_outputs, failed to refresh data from the node")
        return resp[1]

    def retrieve_summary_info(self, minimum_confirmations=1, refresh=True):
        """Return wallet balance"""
        params = {
            'token': self._token,
            'minimum_confirmations': minimum_confirmations,
            'refresh_from_node': refresh,
            }
        resp = self._secure_api_call('retrieve_summary_info', params)
        if refresh and not resp[0]:
            # We requested refresh but data was not successfully refreshed
            raise Exception(f"retrieve_outputs, failed to refresh data from the node")
        return resp[1]

    def cancel_tx(self, tx_id=None, tx_slate_id=None, refresh=True):
        params = {
            'token': self._token,
            'tx_id': tx_id,
            'tx_slate_id': tx_slate_id,
            }
        self._secure_api_call('cancel_tx', params)
        return {'tx_id': tx_id, 'tx_slate_id': tx_slate_id}

    def scan(self, start_height=0, delete_unconfirmed=False):
        """
        Scans the entire UTXO set from the node, identify which outputs belong to the given
        wallet update the wallet state to be consistent with what's currently in the UTXO set.
        """
        params = {
            'token': self._token,
            'start_height': start_height,
            'delete_unconfirmed': delete_unconfirmed,
            }
        resp = self._secure_api_call('scan', params)
        return True

    def finalize_tx(self, slate):
        params = {
            'token': self._token,
            'slate': slate,
            }
        resp = self._secure_api_call('finalize_tx', params)
        if resp:
            return resp
        else:
            return None

    def get_stored_tx(self, id=None, slate_id=None):
        params = {
            'token': self._token,
            'id': id,
            'slate_id': slate_id,
            }
        resp = self._secure_api_call('get_stored_tx', params)
        return resp

    def init_send_tx(self, args):
        params = {
            'token': self._token,
            'args': args,
            }
        resp = self._secure_api_call('init_send_tx', params)

        return resp

    def issue_invoice_tx(self, args):
        params = {
            'token': self._token,
            'args': args,
            }
        resp = self._secure_api_call('issue_invoice_tx', params)
        return resp

    def post_tx(self, tx, fluff=False):
        params = {
            'token': self._token,
            'tx': tx,
            'fluff': fluff,
            }
        resp = self._secure_api_call('post_tx', params)
        return True

    def process_invoice_tx(self, slate, args):
        params = {
            'token': self._token,
            'slate': slate,
            'args': args,
            }
        resp = self._secure_api_call('process_invoice_tx', params)
        return resp

    def tx_lock_outputs(self, slate):
        params = {
            'token': self._token,
            'slate': slate,
            "participant_id": 0
            }
        resp = self._secure_api_call('tx_lock_outputs', params)
        return True

    def accounts(self):
        params = {
            'token': self._token,
            }
        resp = self._secure_api_call('accounts', params)
        return resp

    def get_public_address(self, index: int = 0):
        params = {
            'token': self._token,
            "derivation_index": index
            }
        resp = self._secure_api_call('get_public_address', params)
        return resp

    def change_password(self, old, new, name):
        params = {
            'name': name,
            'old': old,
            'new': new,
            }
        resp = self._secure_api_call('change_password', params)
        return True

    def close(self, name=None):
        params = {
            'name': name,
            }
        resp = self._secure_api_call('close_wallet', params)
        return True

    def create_account_path(self, label):
        """Create account, "sub-wallet", different balances and public keys but one master seed"""
        params = {
            'token': self._token,
            'label': label,
            }
        resp = self._secure_api_call('create_account_path', params)
        return resp

    def create_config(
        self, chain_type: str = "Mainnet", wallet_config: dict = None,
        logging_config: dict = None, tor_config: dict = None, epicbox_config: dict = None):
        params = {
            'chain_type': chain_type,
            'wallet_config': wallet_config,
            'logging_config': logging_config,
            'epicbox_config': epicbox_config,
            'tor_config': tor_config,
            }
        self._secure_api_call('create_config', params)
        return True

    def delete_wallet(self, name=None):
        params = {
            'name': name,
            }
        self._secure_api_call('delete_wallet', params)
        return True

    def get_mnemonic(self, password: str = None, name: str = None):
        if password is None:
            password = utils.secret_manager.get(self.config.password)

        params = {
            'name': name,
            'password': password,
            }
        resp = self._secure_api_call('get_mnemonic', params)
        return resp

    def get_top_level_directory(self):
        params = {}
        resp = self._secure_api_call('get_top_level_directory', params)
        return resp

    def get_updater_messages(self, count=1):
        params = {
            'count': count,
            }
        resp = self._secure_api_call('get_updater_messages', params)
        return resp

    def retrieve_payment_proof(self, refresh=True, tx_id=None, tx_slate_id=None):
        params = {
            'token': self._token,
            'refresh_from_node': refresh,
            'tx_id': tx_id,
            'tx_slate_id': tx_slate_id,
            }
        resp = self._secure_api_call('retrieve_payment_proof', params)
        return resp

    def set_active_account(self, label):
        params = {
            'token': self._token,
            'label': label,
            }
        resp = self._secure_api_call('set_active_account', params)
        return True

    def set_top_level_directory(self, dir_path: str):
        params = {
            'dir': dir_path,
            }
        self._secure_api_call('set_top_level_directory', params)
        return True

    def set_tor_config(self, tor_config=None):
        params = {
            'tor_config': tor_config,
            }
        resp = self._secure_api_call('set_tor_config', params)
        return True

    def start_updater(self, frequency):
        params = {
            'token': self._token,
            'frequency': frequency,
            }
        resp = self._secure_api_call('start_updater', params)
        return True

    def stop_updater(self):
        params = {}
        resp = self._secure_api_call('stop_updater', params)
        return True

    def verify_payment_proof(self, proof):
        params = {
            'token': self._token,
            'proof': proof,
            }
        resp = self._secure_api_call('verify_payment_proof', params)
        return resp

    def create_wallet(self, password: str, name: str = None,
                      mnemonic: str = None, mnemonic_length: int = 24):
        params = {
            'name': name,
            'password': password,
            'mnemonic': mnemonic,
            'mnemonic_length': mnemonic_length,
            }
        resp = self._secure_api_call('create_wallet', params)
        return resp

    @staticmethod
    def _prepare_slate(amount, **kwargs):
        amount = int(amount * 10**8)

        args = {
            "src_acct_name": None,
            "amount": amount,
            "minimum_confirmations": 1,
            "max_outputs": 500,
            "num_change_outputs": 1,
            "selection_strategy_is_use_all": False,
            "message": "From Giver Of Epic with love!",
            "target_slate_version": None,
            "payment_proof_recipient_address": None,
            "ttl_blocks": None,
            "send_args": None
            }

        for key, value in kwargs.items():
            args[key] = value

        return args

    def _send_via_http(self, amount: Union[float, int], address: str, **kwargs):
        # Prepare transaction slate with partial data
        print('>> preparing transaction (init_send_tx)')
        transaction = self._prepare_slate(amount, **kwargs)
        address = f'{address}/{self.foreign_api_version}/foreign'
        tx = self.init_send_tx(transaction)

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

    @staticmethod
    def send_to_receiver_via_http(receiver_address: str, transaction: dict):
        """
        Send transaction to receiver's wallet foreign API via HTTPS/S method
        Receiver's wallet have to run and listen for incoming transaction
        :param receiver_address: str, address pointing to valid  epic-wallet listener
        :param transaction: dict, transaction details
        :return dict | None, transaction response data
        """
        method = 'receive_tx'
        payload = {
            'jsonrpc': '2.0',
            'id': 1,
            'method': method,
            'params': [transaction, receiver_address, None]
            }

        response = requests.post(receiver_address, json=payload)
        return utils.parse_api_response(response)

    # TODO: Something wrong with build_coinbase
    def build_coinbase(self, fees: int = 0, height: int = 0, key_id=None):
        method = 'build_coinbase'
        params = {"block_fees": fees}

        response = self._api_call(method, params, api='foreign')
        return utils.parse_api_response(response)

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

    def _encrypt(self, payload) -> dict:
        """
        Encrypt api_call JSON payload with:
         - 32bit secp256k1 ecdh encryption key computed via init_secure_api()_ func,
         - 12bit nonce,
         - 16bit tag
        :param payload: json payload to encrypt
        :return: dict with base64 encoded AES-256-GMC encrypted payload and nonce as hex string
        """
        nonce = os.urandom(12)
        message = json.dumps(payload).encode()
        aes_cipher = AES.new(bytes.fromhex(self._encryption_key), AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = aes_cipher.encrypt_and_digest(message)
        encrypted_params = {'nonce': nonce.hex(), 'body_enc': base64.b64encode(ciphertext + tag).decode()}

        return encrypted_params

    def _decrypt(self, data, nonce) -> str:
        """ Decrypt base64 encoded string
        :param data: encrypted message
        :param nonce: 12bit nonce as hex string
        :return: decoded string with JSON response
        """
        data = base64.b64decode(data)
        ciphertext = data[:-16]
        aesCipher = AES.new(bytes.fromhex(self._encryption_key), AES.MODE_GCM, nonce=nonce)
        plaintext = aesCipher.decrypt(ciphertext)

        return plaintext.decode()

    def _api_call(self, method: str, params: dict, api: str = 'owner'):
        """
        :param method: api call method name
        :param params: dict with api_call params
        :params api: str, type of api (foreign or owner)
        :return: dict | None
        """
        payload = {
            'jsonrpc': '2.0',
            'id': 1,
            'method': method,
            'params': params
            }

        api_url = getattr(self, f"{api}_api")[0]

        try:
            response = requests.post(api_url, json=payload, auth=self.auth)
            return utils.parse_api_response(response)
        except Exception:
            raise SystemExit(f'Connection error, is wallet owner_api running under: {api_url}?')
