from typing import Union

import requests

from .. import utils
from ..utils import logger


class HTTPHandler:
    """
    Handler for HTTP calls to Epic-Cash server.
    """

    def __init__(self, url: str, auth_user: str, auth_pass: str):
        """
        :param url: string, node api url (local default 127.0.0.1)
        :param auth_user: string, username for authentication
        :param auth_pass: string,
        """
        logger.info(f'Initialized HTTP handler ({url})..')
        self.auth_user = auth_user
        self.auth_pass = auth_pass
        self.call_type: str = ''
        self.url = url

    def api_call(self, method: str, params: Union[list, dict]) -> dict:
        """ Prepare and execute POST request to Node API
        :param method: string, api call method
        :param params: dictionary, params for POST request
        :return: dictionary, parsed response
        """
        payload = {
            'jsonrpc': '2.0',
            'id': 1,
            'method': method,
            'params': params
            }
        url = f"{self.url}/{self.call_type}"
        auth = (self.auth_user, self.auth_pass)
        print(url, auth)
        try:
            response = requests.post(url, json=payload,  timeout=10)
            return utils.parse_api_response(response)
        except requests.exceptions.ConnectionError:
            raise SystemExit(f'Connection error, check provided node API URL, is server running?')

    @staticmethod
    def foreign_method(func):
        """Decorator for foreign (public) methods"""
        def wrapper(self, *args, **kwargs):
            self.call_type = 'foreign'
            return func(self, *args, **kwargs)

        return wrapper

    @staticmethod
    def owner_method(func):
        """Decorator for owner (private) methods"""
        def wrapper(self, *args, **kwargs):
            self.call_type = 'owner'
            return func(self, *args, **kwargs)

        return wrapper

    #### ==== FOREIGN METHODS
    @foreign_method
    def get_version(self):
        """ Get node status and update instance
        :return: dict with node status details
        """
        return self.api_call('get_version', [])["result"]["Ok"]

    @foreign_method
    def get_tip(self):
        """ Get node node tip - height, etc
        :return: dict with node status details
        """
        return self.api_call('get_tip', [])["result"]["Ok"]

    @foreign_method
    def get_block(self, height=None, hash_=None, commit=None) -> dict:
        """
        :param height: int
        :param commit: string
        :param hash_: string
        :return: dict
        """
        resp = self.api_call('get_block', [height, hash_, commit])
        return resp

    @foreign_method
    def get_header(self, height=None, hash_=None, commit=None):
        """
        :param height: int
        :param hash_: string
        :param commit: string
        :return:
        """
        resp = self.api_call('get_header', [height, hash_, commit])
        return resp

    @foreign_method
    def get_kernel(self, kernel, min_height: int = None, max_height: int = None):
        """
        :param kernel: string
        :param min_height: int
        :param max_height: int
        :return: dict
        """
        resp = self.api_call('get_kernel', [kernel, min_height, max_height])
        return resp["result"].get("Ok")

    @foreign_method
    def get_outputs(self, commits: list, start_height: int = None, end_height: int = None,
                    include_proof: bool = True, include_merkle_proof: bool = True):
        """
        :param commits:
        :param end_height:
        :param start_height:
        :param include_proof:
        :param include_merkle_proof:
        :return: dict
        """
        resp = self.api_call('get_outputs', [commits, start_height, end_height,
                                             include_proof, include_merkle_proof])
        return resp["result"].get("Ok")

    @foreign_method
    def get_pmmr_indices(self, start_block_height: int = None, end_block_height: int = None):
        """
        :param start_block_height:
        :param end_block_height:
        :return: dict
        """
        resp = self.api_call('get_pmmr_indices', [start_block_height, end_block_height])
        return resp["result"].get("Ok")

    @foreign_method
    def get_unspent_outputs(self, start_index: int = None, end_index: int = None,
                            max_: int = None, include_proof: bool = True):
        """
        :param max_:
        :param start_index:
        :param end_index:
        :param include_proof:
        :return: dict
        """
        resp = self.api_call('get_unspent_outputs', [start_index, end_index, max_, include_proof])
        return resp["result"].get("Ok")

    @foreign_method
    def get_pool_size(self):
        """
        :return: dict
        """
        return self.api_call('get_pool_size', [])["result"]["Ok"]

    @foreign_method
    def get_stempool_size(self):
        """
        :return: dict
        """
        return self.api_call('get_stempool_size', [])["result"]["Ok"]

    @foreign_method
    def get_unconfirmed_transactions(self):
        """
        :return: dict
        """
        return self.api_call('get_unconfirmed_transactions', {})["result"]["Ok"]

    @foreign_method
    def push_transaction(self, transaction: dict):
        """
        :return: dict
        """
        return self.api_call('push_transaction', [transaction])["result"]["Ok"]

    #### ==== OWNER METHODS
    @owner_method
    def get_status(self) -> dict:
        """ Get node status and update instance
        :return: dict with node status details
        """
        return self.api_call('get_status', [])["result"]["Ok"]

    @owner_method
    def validate_chain(self) -> None:
        """ Trigger a validation of the chain state.
        :return: None
        """
        return self.api_call('validate_chain', [])["result"]["Ok"]

    @owner_method
    def compact_chain(self) -> None:
        """ Trigger a compaction of the chain state to regain storage space.
        :return: None
        """
        return self.api_call('compact_chain', [])["result"]["Ok"]

    @owner_method
    def get_peers(self, peers: list = None) -> list:
        """ Retrieves information about stored peers
        If None is provided, will list all stored peers
        :param peers: list of peers `address:port` to retrieve
        :return: list
        """
        return self.api_call('get_peers', peers)["result"]["Ok"]

    @owner_method
    def get_connected_peers(self) -> list:
        """
        :return: list of connected peers
        """
        return self.api_call('get_connected_peers', [])["result"]["Ok"]

    @owner_method
    def ban_peer(self, peer_address: str) -> None:
        """Ban a specific `address:port` peer.
        :return: None
        """
        return self.api_call('ban_peer', [peer_address])["result"]["Ok"]

    @owner_method
    def unban_peer(self, peer_address: str) -> None:
        """Un-ban a specific `address:port` peer.
        :return: None
        """
        return self.api_call('unban_peer', [peer_address])["result"]["Ok"]