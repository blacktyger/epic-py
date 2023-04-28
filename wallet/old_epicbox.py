from typing import Union
import json

import epic_wallet_rust_python as r_lib
import requests

from ..utils import logger
from .. import utils
from . import models


class EpicBoxHandler:
    """
    Class to manage epic-box connection and transaction flow.
    """

    def __init__(self, wallet_config: models.WalletConfig):
        # self.stop_listener = True
        self.wallet_config = wallet_config
        self.epicbox: models.EpicBoxConfig
        self._load_cfg()

    def _load_cfg(self):
        """Initialize epicbox settings and check server connection"""
        try:
            self.epicbox = models.EpicBoxConfig()
            address = self._parse_rust(
                self._run(
                    r_lib.get_epicbox_address_py,
                    domain=self.epicbox.domain,
                    port=self.epicbox.port)
                )
            address = address.split('//')[-1].split('@')[0]
            self.epicbox.address = address
            self.epicbox.init_config()

        except Exception as e:
            logger.error(f">> loading epicbox config failed: {e}")

        # Check connection to the epic-box server
        try:
            r = requests.get(self.epicbox.api_url)
            if r.status_code in [200, 2001]:
                logger.info(f">> Connected to epic-box server")
            else:
                logger.error(f">> failed connection to epic-box server \n {r.content}")
        except Exception as e:
            logger.error(f">> connecting to epicbox server failed: {e}")

    @staticmethod
    def _parse_rust(response: str):
        if not response:
            logger.error(f">> ERROR: 'Unknown'")
            return None

        response = json.loads(response)

        if response['error']:
            if 'Wallet store error: DB Not Found Error' in response['message']:
                logger.warning(f">> Transaction already processed.")
                return None
            else:
                logger.error(f">> '{response['message']}'")
            return None

        if 'success' not in response['message']:
            logger.warning(f">> '{response['message']}'")

        return response['result']

    @staticmethod
    def _parse_epicbox(response: requests.Response):
        if response.status_code not in [200, 2001]:
            logger.error(f">> ERROR: '{response.content}'")
            return []

        response = response.json()
        status = response['status']

        if 'failure' in status:
            message = response['error'] if 'error' in response else 'Unknown'
            print(f">> ERROR: '{message}'")
            return []

        logger.info(f">> EpicBoxResponse(status={status})")

        if 'is_deleted' in response:
            return response['is_deleted']
        if 'slates' in response:
            return response['slates']
        if 'canceled_slates' in response:
            return response['canceled_slates']
        else:
            return response

    def _run(self, func, **kwargs):
        """
        Wrapper for running functions from wallet RUST library
        :param func:
        :param kwargs:
        :return:
        """
        print(f"\n"
              f"{self.wallet_config.as_json()}"
              f"\n")
        try:
            return func(config=self.wallet_config.as_json(),
                        password=self.wallet_config.password, **kwargs)
        except Exception as e:
            logger.error(f">> RUST ERROR: {e}")

    def _get_signature(self):
        """
        Create a signature for epic-box requests
        :returns
        """
        request = self._run(r_lib.subscribe_request_py, epicbox_config=self.epicbox.as_json())
        return json.loads(self._parse_rust(request))['signature']

    def create_tx_slate(self,
                        amount: Union[int, float],
                        min_confirmations: int = 1,
                        use_all_outputs: bool = False
                        ) -> str | None:
        """
        Initialize transaction as sender, create new slate
        :param amount:
        :param min_confirmations:
        :param use_all_outputs:
        :return:
        """
        amount = int(amount * 10 ** 8)
        args = (amount, min_confirmations, use_all_outputs)
        return self._parse_rust(self._run(r_lib.create_tx_py, args=args))

    def cancel_tx_slate(self, slate: str = None, tx_slate_id: str = None) -> str | None:
        """
        Cancel transaction
        :param tx_slate_id:
        :param slate:
        :return:
        """
        if not slate and not tx_slate_id:
            logger.error(f">> slate or tx_slate_id is required")
            return

        if slate and not tx_slate_id:
            tx_slate_id = utils.get_tx_slate_id(slate)

        return self._parse_rust(self._run(r_lib.cancel_tx_py, tx_slate_id=tx_slate_id))

    def post_tx_slate(self, receiver_address: str, slate: str):
        """
        Post prepared slate to epic-box server
        :param receiver_address:
        :param slate:
        :return:
        """
        if not slate:
            return

        request_slate = self._parse_rust(
            self._run(
                r_lib.post_request_py,
                epicbox_config=self.epicbox.as_json(),
                receiver_address=receiver_address,
                slate=slate
                ))

        url = f"{self.epicbox.api_url}/postSlate"
        payload = {'receivingAddress': receiver_address, 'slate': request_slate}
        return self._parse_epicbox(requests.post(url=url, json=payload))

    def get_tx_slates(self) -> list:
        """
        :return:
        """
        url = f"{self.epicbox.api_url}/getSlates"
        payload = {'receivingAddress': self.epicbox.address,
                   'signature': self._get_signature()}
        encrypted_slates = self._parse_epicbox(
            requests.post(url=url, json=payload))

        return encrypted_slates

    def decrypt_tx_slates(self, slates: list) -> list:
        """
        :param slates:
        :return:
        """
        # print(slates)
        decrypted = self._parse_rust(self._run(r_lib.decrypt_slates_py,
                                     encrypted_slates=json.dumps(slates)))
        return [json.loads(slate) for slate in decrypted]

    def process_tx_slates(self, slates: list) -> list:
        """
        :param slates:
        :return:
        """
        processed = []

        for slate in slates:
            if '[null, null]' in slate:
                continue

            if 'PendingProcessing' in slate[0]:
                try:
                    slate = json.loads(slate[0])
                    slate = json.loads(slate[0])[1]
                except KeyError:
                    slate = slate[1]
            elif 'TxReceived' in slate[0]:
                slate = json.dumps(slate)
            else:
                slate = slate[0]

            # print('python >>', slate)
            response = self._parse_rust(self._run(r_lib.process_slate_py, slate=slate))
            if response:
                processed.append(response)
                logger.info(self.post_delete_tx_slate(self.epicbox.address, slate))

        return processed

    def post_transaction(self, finalize_slate: str = None, tx_slate_id: str = None):
        """
        :param tx_slate_id:
        :param finalize_slate:
        :return:
        """
        if not finalize_slate and not tx_slate_id:
            logger.error(f">> slate or tx_slate_id is required")
            return

        if finalize_slate and not tx_slate_id:
            tx_slate_id = utils.get_tx_slate_id(finalize_slate)

        return self._parse_rust(self._run(r_lib.post_tx_py, tx_slate_id=tx_slate_id))

    def get_transactions(self) -> list:
        """
        :return: list, local transaction history of the wallet instance
        """
        transactions = self._parse_rust(self._run(r_lib.get_txs_py))
        return json.loads(transactions)

    def post_cancel_transaction(self,
                                receiving_address: str,
                                slate: str = None,
                                tx_slate_id: str = None) -> list | dict:
        """
        Call to send cancel request to epic-box server (as sender)
        :param tx_slate_id:
        :param receiving_address:
        :param slate:
        :return:
        """
        if not slate and not tx_slate_id:
            logger.error(f">> slate or tx_slate_id is required")
            return []

        if slate and not tx_slate_id:
            tx_slate_id = utils.get_tx_slate_id(slate)

        url = f"{self.epicbox.api_url}/postCancel"
        payload = {'receivingAddress': receiving_address,
                   'sendersAddress': self.epicbox.address,
                   'signature': self._get_signature(),
                   'slate': tx_slate_id}
        return self._parse_epicbox(requests.post(url=url, json=payload))

    def post_delete_tx_slate(self, receiving_address: str, slate: str) -> list:
        """
        :param receiving_address:
        :param slate:
        :return:
        """
        if not isinstance(slate, str):
            slate = json.dumps(slate)

        url = f"{self.epicbox.api_url}/deleteSlate"
        payload = {'receivingAddress': receiving_address,
                   'signature': self._get_signature(),
                   'slate': slate}
        return self._parse_epicbox(requests.post(url=url, json=payload))

    def get_canceled_tx_slates(self) -> list:
        """
        :return:
        """
        url = f"{self.epicbox.api_url}/getCancels"
        payload = {'receivingAddress': self.epicbox.address,
                   'signature': self._get_signature()}
        return self._parse_epicbox(requests.post(url=url, json=payload))

    def post_delete_canceled_tx_slates(self, receiving_address: str,
                                       slate: str = None, tx_slate_id: str = None) -> list:
        """
        :param tx_slate_id:
        :param receiving_address:
        :param slate:
        :return:
        """
        if not slate and not tx_slate_id:
            logger.error(f">> slate or tx_slate_id is required")
            return []

        if slate and not tx_slate_id:
            tx_slate_id = utils.get_tx_slate_id(slate)

        url = f"{self.epicbox.api_url}/deleteCancels"
        payload = {'receivingAddress': receiving_address,
                   'signature': self._get_signature(),
                   'slate': tx_slate_id}
        return self._parse_epicbox(requests.post(url=url, json=payload))

    # def run_listening(self):
    #     logger.info(f">> Starting EPIC-BOX listener for "
    #           f"{self.epicbox.get_short_address()}")
    #     self.stop_listener = False
    #     self.listener_thread = threading.Thread(target=self._listener)
    #     self.listener_thread.start()
    #
    # def stop_listening(self):
    #     logger.info(f">> Stopping EPIC-BOX listener for "
    #          f"{self.epicbox.get_short_address()}")
    #     self.stop_listener = True
    #
    # def _listener(self):
    #     """
    #     Background process (thread) to listen for incoming from
    #     epic-box server transaction slates.
    #     :return:
    #     """
    #     INTERVAL = 3
    #
    #     while not self.stop_listener:
    #         self.get_tx_slates()
    #         time.sleep(INTERVAL)
    #
    #     self.listener_thread = None

    def _send_via_epicbox(self, amount: Union[float, int], address: str, **kwargs):
        # Prepare transaction slate with partial data
        logger.info('>> preparing transaction (create_tx_slate)')
        new_tx = self.create_tx_slate(amount=amount)

        logger.info('>> sending slate to epic-box (post_tx_slate)')
        post_new_tx_slate = self.post_tx_slate(address, new_tx)

        if not post_new_tx_slate:
            deleted = self.cancel_tx_slate(slate=new_tx)
            logger.warning(f">> Transaction {utils.get_tx_slate_id(slate=new_tx)} failed and deleted: {deleted}")
