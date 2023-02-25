import subprocess
import platform
import shutil
import json
import time
import uuid
import os

from pydantic import BaseModel, Field
from toml import TOMLConfig


if 'windows' in platform.system().lower():
    HOME_DIR = '%USERPROFILE%'
else:
    HOME_DIR = '~'

SOURCE_PATH = "/home/blacktyger/epic-wallet/target/release"
PUBLIC_NODE = 'https://fastepic.eu:3413'
BINARY_NAME = 'epic-wallet'
PASSWORD = 'majkut11'
NETWORK = 'mainnet'


class WalletModel:
    network: str = None
    password: str = None
    wallet_id: str = str(uuid.uuid4())
    source_path: str = None
    description: str = ''
    binary_name: str = None
    wallet_name: str = f'wallet_{wallet_id}'
    node_address: str = None
    wallet_data_directory: str = None

    def __init__(self, **kwargs):
        required_args = ('network', 'password', 'source_path', 'binary_name')

        for k, v in kwargs.items():
            setattr(self, k, v)

        if not self.wallet_data_directory:
            self.wallet_data_directory = os.path.join(os.getcwd(), self.wallet_name)

        if not all(arg in kwargs for arg in required_args):
            raise SystemExit(f'Missing required argument/s, provide all: {required_args}') from None

    def json(self):
        d = self.__dict__.copy()
        return json.dumps(d)


def create(**kwargs):
    model = WalletModel(**kwargs)
    print(model.json())

    source_full_path = os.path.join(model.source_path, model.binary_name)

    if not os.path.isfile(source_full_path):
        raise SystemExit(f'Invalid source {source_full_path} binary file path') from None

    os.makedirs(model.wallet_data_directory, exist_ok=True)
    shutil.copy(source_full_path, model.wallet_data_directory)
    os.chdir(model.wallet_data_directory)

    print(os.getcwd())

    # Add 'enter' to password and encode to bytes
    pass_ = f"{model.password}\n".encode()
    args = f"./{model.binary_name} -r {model.node_address} -p {PASSWORD} init -h"

    # Create new wallet and its directories
    subprocess.Popen(args.split(' '))
    time.sleep(1)

    # Update settings
    config_file = os.path.join(model.wallet_data_directory, f"{model.binary_name}.toml")
    config = TOMLConfig(path=config_file)

    if model.node_address:
        config.set(category='wallet', key='check_node_api_http_addr', value=model.node_address)

    # Show wallet info
    args = f'./{model.binary_name} info'
    info_wallet = subprocess.Popen(args.split(' '), stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    # Provide pass as input, not argument (security)
    print(info_wallet.communicate(input=pass_))


if __name__ == '__main__':
    create(
        network=NETWORK,
        binary_name=BINARY_NAME,
        source_path=SOURCE_PATH,
        node_address=PUBLIC_NODE,
        password=PASSWORD
        )
