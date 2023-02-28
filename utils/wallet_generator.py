import subprocess
import platform
import shutil
import json
import uuid
import os

from secret_manager import set_secret_value, get_secret_value
from toml import TOMLConfig


if 'windows' in platform.system().lower():
    HOME_DIR = '%USERPROFILE%'
else:
    HOME_DIR = '~'

class WalletModel:
    id: str = str(uuid.uuid4())
    name: str = f'wallet_{id}'
    network: str = None
    password: str = None
    source_path: str = None
    description: str = ''
    binary_name: str = None
    node_address: str = None
    epicbox_address: str = None
    wallet_data_directory: str = None

    def __init__(self, **kwargs):
        required_args = ('network', 'password', 'source_path', 'binary_name')

        for k, v in kwargs.items():
            setattr(self, k, v)

        if not self.wallet_data_directory:
            self.wallet_data_directory = os.path.join(os.getcwd(), self.name)

        if not all(arg in kwargs for arg in required_args):
            raise SystemExit(f'Missing required argument/s, provide all: {required_args}') from None

    def json(self):
        d = self.__dict__.copy()
        return json.dumps(d)


def create(**kwargs):
    wallet = WalletModel(**kwargs)
    source_full_path = os.path.join(wallet.source_path, wallet.binary_name)

    # Make sure source wallet-cli file exists
    if not os.path.isfile(source_full_path):
        raise SystemExit(f'Invalid wallet-cli {source_full_path} binary file path') from None

    # Create new top_dir wallet directory and copy source binary there
    os.makedirs(wallet.wallet_data_directory, exist_ok=True)
    shutil.copy(source_full_path, wallet.wallet_data_directory)
    os.chdir(wallet.wallet_data_directory)

    # Build full wallet init command
    args = f"./{wallet.binary_name} -r {wallet.node_address} -p {wallet.password} init -h"

    # Create new wallet and its init data
    init_wallet = subprocess.Popen(args.split(' ')).wait()

    # Load created by wallet settings file to TomlConfig object
    config_file = os.path.join(wallet.wallet_data_directory, f"{wallet.binary_name}.toml")
    config = TOMLConfig(path=config_file)

    # Update / override default wallet settings
    if wallet.node_address:
        config.set(category='wallet', key='check_node_api_http_addr', value=wallet.node_address)

    if wallet.epicbox_address:
        config.set(category='epicbox', key='epicbox_domain', value=wallet.epicbox_address)

    if 'debug' in kwargs and kwargs['debug']:
        config.set(category='logging', key='stdout_log_level', value="DEBUG")
        config.set(category='logging', key='file_log_level', value="DEBUG")

    # Save password to secure storage with pass manager
    set_secret_value(f"{PASSWORD_STORAGE_PATH}/{wallet.id}", value=wallet.password)
    wallet.password = None

    # Show wallet info
    args = f'./{wallet.binary_name} info'
    info_wallet = subprocess.Popen(args.split(' '), stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

    # Provide pass as input, not argument (security)
    print(info_wallet.communicate(input=get_secret_value(f"{PASSWORD_STORAGE_PATH}/{wallet.id}"))[0])

    return wallet


if __name__ == '__main__':
    wallet = create(
        debug=True,
        network=NETWORK,
        password=PASSWORD,
        binary_name=BINARY_NAME,
        source_path=SOURCE_PATH,
        node_address=PUBLIC_NODE,
        epicbox_address=EPICBOX_NODE
        )

    print(wallet.json())