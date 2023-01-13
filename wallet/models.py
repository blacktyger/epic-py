from typing import Any
import json
import os

from pydantic import BaseModel, Field

from .. import utils


class WalletConfig(utils.TOMLConfig):
    def __init__(self, wallet_dir: str, password: str, **kwargs):
        self.config_file = os.path.join(wallet_dir, 'epic-wallet.toml')

        if os.path.isfile(self.config_file):
            super().__init__(self.config_file)

        self.tor = self.settings['tor']
        self.wallet = self.settings['wallet']
        self.logging = self.settings['logging']
        self.password = password
        self.wallet_dir = wallet_dir
        self.account: str = 'default'
        self.account_id: int = 0

        for key, value in kwargs.items():
            setattr(self, key, value)

    def as_json(self):
        return json.dumps({
            'chain': self.wallet['chain_type'].lower(),
            'account': self.account,
            'wallet_dir': self.wallet_dir,
            'check_node_api_http_addr': self.wallet['check_node_api_http_addr'],
            'api_listen_interface': self.wallet['api_listen_interface'],
            'api_listen_port': self.wallet['owner_api_listen_port'],
            })

    def essential(self, pass_path: str):
        # For security reasons 'password' key is not password itself
        # but path to encrypted file

        return {'password': pass_path, 'wallet_dir': self.wallet_dir}

    def __str__(self):
        return f"WalletConfig(path='{self.config_file}')"


class EpicBoxConfig(BaseModel):
    prefix: str | None = Field('epicbox')
    domain: str | None = Field(default='epicpost.stackwallet.com')
    port: str | None = Field(default=0)
    address: str | None = Field(default='')
    full_address: str | None
    api_url: str | None

    def __init__(self, **data: Any):
        super().__init__(**data)
        self.init_config()

    def init_config(self):
        _full_address = f"{self.prefix}://{self.address}@{self.domain}"

        if self.port:
            _full_address += f"{_full_address}:{self.port}"

        self.full_address = _full_address
        self.api_url = f"https://{self.domain}"

    def get_short_address(self):
        return f"{self.address[0:4]}...{self.address[-4:]}"

    def as_json(self):
        return self.json(include={'domain', 'port'})

    def __str__(self):
        return f"EpicBox(address='{self.address}')"

