from typing import Any
import json
import os

from pydantic import BaseModel, Field

from epicpy import utils


class WalletConfig(utils.TOMLConfig):
    def __init__(self, wallet_dir: str, **kwargs):
        self.config_file = os.path.join(wallet_dir, 'epic-wallet.toml')
        super().__init__(self.config_file)

        self.tor = self.settings['tor']
        self.wallet = self.settings['wallet']
        self.logging = self.settings['logging']
        self.account: str = 'default'
        self.account_id: int = 0
        self.wallet_dir = wallet_dir

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

    def __str__(self):
        return f"WalletConfig(path='{self.config_file}')"


class EpicBox(BaseModel):
    prefix: str | None = Field('epicbox')
    domain: str | None = Field(default='epicpost.stackwallet.com')
    port: str | None = Field(default=0)
    address: str | None = Field(default='')
    full_address: str | None

    def __init__(self, **data: Any):
        super().__init__(**data)
        self.get_full_address()

    def get_full_address(self):
        result = f"{self.prefix}://{self.address}@{self.domain}"
        if self.port: result += f"{result}:{self.port}"
        self.full_address = result

    def as_json(self):
        return self.json(include={'domain', 'port'})

    def __str__(self):
        return f"EpicBox(address='{self.address}')"

