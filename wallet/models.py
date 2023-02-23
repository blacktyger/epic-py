from typing import Any
import json
import os

from pydantic import BaseModel, Field

from .. import utils

EPICBOX_DOMAIN = 'epic.tech'
EPICBOX_PORT = 0


class Account(BaseModel):
    id: int | None = Field(default=0)
    name: str | None = Field(default='default')


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
        self.accounts: list = [Account(id=0, name='default')]

        for key, value in kwargs.items():
            setattr(self, key, value)

    def __str__(self):
        return f"WalletConfig({self.wallet_dir})"


class EpicBoxConfig(BaseModel):
    address: str | None = Field(default='')
    prefix: str | None = Field('epicbox')
    domain: str | None = Field(default=EPICBOX_DOMAIN)
    port: str | None = Field(default=EPICBOX_PORT)
    full_address: str | None

    def __init__(self, **data: Any):
        super().__init__(**data)
        self.init_config()

    def init_config(self):
        _full_address = f"{self.address}@{self.prefix}.{self.domain}"

        if self.port:
            _full_address = f"{_full_address}:{self.port}"

        self.full_address = _full_address

    def get_short_address(self):
        return f"{self.address[0:4]}...{self.address[-4:]}"

    def __str__(self):
        return f"EpicBox({self.address})"

