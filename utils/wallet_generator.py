import os
import subprocess
import uuid
import shutil

import platform
from pydantic import BaseModel, Field

from wallet.epic_sdk.wallet import Wallet


if 'windows' in platform.system().lower():
    HOME_DIR = '%USERPROFILE%'
else:
    HOME_DIR = '~'

PUBLIC_NODE = 'https://epic-radar.com/node'


class CreateWalletModel(BaseModel):
    source_path: str | None = Field(default=os.getcwd())
    description: str | None = Field(default='')
    binary_name: str | None = Field(default='epic-wallet')
    wallet_id: str | None = Field(default=uuid.uuid4())
    password: str | None = Field(...)
    wallet_name: str | None = Field(default=f'wallet_{wallet_id}')
    network: str | None = Field(default='mainnet')
    wallet_data_directory: str | None = Field(default=f'{HOME_DIR}/.epic/{network}/{binary_name}s/{wallet_name}')


def create(**kwargs):
    model = CreateWalletModel(**kwargs)
    source_full_path = f'{model.source_path}/{model.binary_name}'

    if not os.path.isfile(source_full_path):
        raise SystemExit(f'Invalid source {source_full_path} binary file path') from None

    os.makedirs(model.wallet_data_directory, exist_ok=True)
    shutil.copy(source_full_path, model.wallet_data_directory)
    os.chdir(model.wallet_data_directory)

    # Add 'enter' to password and encode to bytes
    pass_ = f"{model.password}\n".encode()
    args = f"./{model.binary_name} -r {PUBLIC_NODE} init -h"

    init_wallet = subprocess.Popen(args.split(' '), stdin=subprocess.PIPE)

    # Provide pass as input, not argument (security)
    init_wallet.communicate(input=pass_)
    init_wallet.communicate(input=pass_)


if __name__ == '__main__':
    # create(source_path='/home/blacktyger/epic-wallet/target/release', password='majkut11')
    print(os.path.isdir("/home/blacktyger/epic-wallet/target/release/"))