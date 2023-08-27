import json
from pathlib import Path
import asyncio
import sys

from grpclib.utils import graceful_exit
from grpclib.server import Server, Stream

sys.path.append(str(Path('.').absolute().parent))
sys.path.append(str(Path('.').absolute().parent.parent))
sys.path.append(str(Path('.').absolute().parent.parent.parent))
from src import Wallet, utils

# generated by protoc
from server_pb2 import WalletRequest, WalletResponse
from server_grpc import WalletServerBase


SUCCESS = False
ERROR = True


class WalletServer(WalletServerBase):
    def __init__(self):
        self.wallet = Wallet()

    async def Call(self, stream: Stream[WalletRequest, WalletResponse]) -> None:
        request = await stream.recv_message()

        try:
            assert request is not None

            match request.call:
                case 'create':
                    response = await self.create_new(request.data)
                    await stream.send_message(WalletResponse(result=response))

                case 'open':
                    response = await self.open(request.data)
                    await stream.send_message(WalletResponse(result=response))

                case 'balance':
                    response = await self.balance(request.data)
                    await stream.send_message(WalletResponse(result=response))

                case 'fees':
                    response = await self.fees(request.data)
                    await stream.send_message(WalletResponse(result=response))

                case 'create_outputs':
                    response = await self.create_outputs(request.data)
                    await stream.send_message(WalletResponse(result=response))

                case 'send_epicbox':
                    response = await self.send_epicbox(request.data)
                    await stream.send_message(WalletResponse(result=response))

                case 'send_cli':
                    response = await self.send_cli(request.data)
                    await stream.send_message(WalletResponse(result=response))

                case 'send_file':
                    response = await self.send_file(request.data)
                    await stream.send_message(WalletResponse(result=response))

                case 'receive_file':
                    response = await self.receive_file(request.data)
                    await stream.send_message(WalletResponse(result=response))

                case 'finalize_file':
                    response = await self.finalize_file(request.data)
                    await stream.send_message(WalletResponse(result=response))

                case _:
                    response = json.dumps(utils.response(ERROR, f'call {request.call} is not recognized'))
                    await stream.send_message(WalletResponse(result=response))

        except Exception as e:
            response = json.dumps(utils.response(ERROR, str(e)))
            await stream.send_message(WalletResponse(result=response))

    async def create_new(self, data: str):
        try:
            kwargs = json.loads(data)
            created = await self.wallet.create_new(**kwargs)

            if not created['error']:
                return json.dumps(utils.response(SUCCESS, 'wallet created'))
            else:
                return json.dumps(created)

        except Exception as e:
            return json.dumps(utils.response(ERROR, str(e)))

    async def open(self, data: str):
        try:
            kwargs = json.loads(data)

            if 'long_running' in kwargs:
                self.wallet = Wallet(path=kwargs['wallet_data_directory'], long_running=kwargs['long_running'])

            if 'open' in kwargs and kwargs['open']:
                await self.wallet.api_http_server.open()

            if 'epicbox' in kwargs and kwargs['epicbox']:
                await self.wallet.run_epicbox()

            return json.dumps(utils.response(SUCCESS, 'wallet opened', kwargs))

        except Exception as e:
            return json.dumps(utils.response(ERROR, str(e)))

    async def balance(self, data: str = None):
        try:
            kwargs = {}

            if data:
                kwargs = json.loads(data)

            balance = await self.wallet.get_balance(**kwargs)
            return json.dumps(utils.response(SUCCESS, 'wallet opened', balance.json()))

        except Exception as e:
            return json.dumps(utils.response(ERROR, str(e)))

    async def fees(self, data: str):
        try:
            kwargs = json.loads(data)
            fees = await self.wallet.calculate_fees(**kwargs)
            return json.dumps(utils.response(SUCCESS, 'wallet opened', str(fees)))

        except Exception as e:
            return json.dumps(utils.response(ERROR, str(e)))

    async def create_outputs(self, data: str):
        try:
            kwargs = json.loads(data)
            outputs = await self.wallet.create_outputs(**kwargs)
            return json.dumps(outputs)

        except Exception as e:
            return json.dumps(utils.response(ERROR, str(e)))

    async def send_epicbox(self, data: str):
        try:
            kwargs = json.loads(data)
            tx = await self.wallet.send_epicbox_tx(**kwargs)
            return json.dumps(tx)

        except Exception as e:
            return json.dumps(utils.response(ERROR, str(e)))

    async def send_cli(self, data: str):
        try:
            kwargs = json.loads(data)
            tx = self.wallet.send_via_cli(**kwargs)
            return json.dumps(tx)

        except Exception as e:
            return json.dumps(utils.response(ERROR, str(e)))

    async def send_file(self, data: str):
        try:
            kwargs = json.loads(data)
            tx = self.wallet.send_file_tx(**kwargs)
            return json.dumps(tx)

        except Exception as e:
            return json.dumps(utils.response(ERROR, str(e)))

    async def receive_file(self, data: str):
        try:
            kwargs = json.loads(data)
            tx = self.wallet.receive_file_tx(**kwargs)
            return json.dumps(tx)

        except Exception as e:
            return json.dumps(utils.response(ERROR, str(e)))

    async def finalize_file(self, data: str):
        try:
            kwargs = json.loads(data)
            tx = self.wallet.finalize_file_tx(**kwargs)
            return json.dumps(tx)

        except Exception as e:
            return json.dumps(utils.response(ERROR, str(e)))


async def main(*, host: str = '127.0.0.1', port: int = 50051) -> None:
    server = Server([WalletServer()])
    # Note: graceful_exit isn't supported in Windows
    with graceful_exit([server]):
        await server.start(host, port)
        print(f'Serving on {host}:{port}')
        await server.wait_closed()


if __name__ == '__main__':
    asyncio.run(main())