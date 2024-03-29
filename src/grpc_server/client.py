from pathlib import Path
import asyncio
import json
import sys

from grpclib.client import Channel

sys.path.append(str(Path('.').absolute().parent))
sys.path.append(str(Path('.').absolute().parent.parent))
sys.path.append(str(Path('.').absolute().parent.parent.parent))

from src import utils
from server_pb2 import WalletRequest
from server_grpc import WalletServerStub


async def main():
    async with Channel('127.0.0.1', 50051) as channel:
        wallet = WalletServerStub(channel)

        create_new = {'call': 'create', 'data': json.dumps({
            'name': 'test',
            'debug': True,
            'password': utils.defaults.PASSWORD,
            'node_address': utils.defaults.PUBLIC_NODE,
            'binary_file_path': utils.defaults.BINARY_PATH,
            'wallet_data_directory': '/home/blacktyger/python-sdk/tests/epic-wallet',
            })}

        open_wallet = {'call': 'open', 'data': json.dumps({
            'wallet_data_directory': '/home/blacktyger/python-sdk/tests/epic-wallet',
            'long_running': True,
            'open': True,
            'epicbox': True
            })}

        oclose_wallet = {'call': 'close', 'data': json.dumps({
            'wallet_data_directory': '/home/blacktyger/python-sdk/tests/epic-wallet',
            'close_epicbox': True
            })}

        balance = {'call': 'balance', 'data': json.dumps({
            'get_outputs': False,
            'cached_time_tolerance': 10,
            })}

        fees = {'call': 'fees', 'data': json.dumps({
            'amount': 0.05,
            })}

        send_epicbox = {'call': 'send_epicbox', 'data': json.dumps({
            'amount': 0.01,
            'address': 'esa3LDpTJZzFjtoPaagaHxJnsAZb5PfekMuD2RNncExVY4BjUkt3@epicbox.epic.tech'
            })}

        create_outputs = {'call': 'create_outputs', 'data': json.dumps({
            'num': 3,
            })}

        transactions = {'call': 'transactions', 'data': json.dumps({
            'status': 'cancelled',
            'tx_type': 'sent',
            'tx_slate_id': None,
            'refresh': False,
            })}

        cancel_tx = {'call': 'cancel_tx', 'data': json.dumps({
            'tx_slate_id': None,
            })}

        send_cli = {'call': 'send_cli', 'data': json.dumps({
            'amount': 0.01,
            'address': '',
            'method': 'self',
            'confirmations': 1,
            'outputs': 1,
            'selection_strategy': 'smallest'
            })}

        send_file = {'call': 'send_file', 'data': json.dumps({
            'amount': 0.05,
            'file_name': ''
            })}

        receive_file = {'call': 'receive_file', 'data': json.dumps({
            'init_tx_file': '',
            'response_tx_file': ''
            })}

        finalize_file = {'call': 'finalize_file', 'data': json.dumps({
            'response_tx_file': '',
            })}

        # reply = await wallet.Call(WalletRequest(**open_wallet))
        # print(reply.result)
        reply = await wallet.Call(WalletRequest(**transactions))
        print(reply.result)

if __name__ == '__main__':
    asyncio.run(main())