import time
from typing import Any
import subprocess
import uuid
import os

from pydantic import BaseModel, Field
import tomlkit
import psutil

from utils import logger, find_process_by_port, defaults
from utils.secret_manager import get_secret_value


EPICBOX_DOMAIN = 'epic.tech'
EPICBOX_PORT = 0


class Account(BaseModel):
    id: int
    name: str

    def __str__(self):
        return f"Account({self.name}, [{self.id}])"


class Settings(BaseModel):
    def __init__(self, file_path: str, **data: Any):
        super().__init__(**data)
        self.file_name = data['file_name'] \
            if 'file_name' in data else 'epic-wallet.toml'
        self.file_path = os.path.join(file_path, self.file_name)

        if not self._valid_file():
            raise SystemExit("Invalid *.toml file path") from None

        self._load_from_file()

    def _valid_file(self):
        if os.path.isfile(self.file_path) and self.file_path.endswith('.toml'):
            return True
        return False

    def _load_from_file(self):
        try:
            with open(self.file_path, 'rt', encoding="utf-8") as file:
                settings_ = tomlkit.load(file)
                for k, v in settings_.items():
                    setattr(self, k, v)
        except Exception as e:
            print(str(e))

    def _save_to_file(self):
        print(self.dict(exclude={'path'}))
        try:
            with open(self.file_path, 'wt', encoding="utf-8") as file:
                tomlkit.dump(self.dict(exclude={'path'}), file)
        except Exception as e:
            print(str(e))

    def get(self, category, key, sub_category=None):
        self._load_from_file()
        try:
            if sub_category:
                return getattr(self, category)[sub_category][key]
            else:
                return getattr(self, category)[key]
        except Exception:
            print(f'"[{category}] {sub_category} {key}" key does not exists')

    def set(self, category, key, value, sub_category=None):
        self._load_from_file()
        try:
            if sub_category:
                setattr(self, category, sub_category[key][value])
            else:
                setattr(self, category, key[value])
        except Exception as e:
            print(e)

        self._save_to_file()


class Config(BaseModel):
    REQUIRED: tuple = ('binary_path', 'password')

    id: str = str(uuid.uuid4())
    name: str = f'wallet_{id}'
    network: str = 'mainnet'
    password: str = None
    binary_path: str = None
    description: str = ''
    binary_name: str = 'epic-wallet'
    node_address: str = None
    epicbox_address: str = None
    wallet_data_directory: str = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        for k, v in kwargs.items():
            if k != 'id':  # Protect id field from overriding
                setattr(self, k, v)

        if not self.wallet_data_directory:
            self.wallet_data_directory = os.path.join(os.getcwd(), self.name)


class Listener(BaseModel):
    settings: Settings
    process: psutil.Process | None = None
    config: Config

    def run(self, method: str):
        match method:
            case 'http':
                key, sub_cat = 'api_listen_port', None
                subcommand = 'listen'
            case 'owner':
                key, sub_cat = 'owner_api_listen_port', None
                subcommand = 'owner_api'
            case 'epicbox':
                key, sub_cat = None, None
                subcommand = 'listen'
            case _:
                logger.error(f'"{method}" is not a valid listening method')
                return

        if key:
            port = self.settings.get(category='wallet', key=key, sub_category=sub_cat)
            external_process_pid = find_process_by_port(port)

            if external_process_pid not in (None, 0, '0'):
                self.process = psutil.Process(int(external_process_pid))
                logger.warning(f"{method} listener already running! {self.process.pid}")
                return self

        if self.process:
            if psutil.pid_exists(self.process.pid):
                logger.warning(f"{method} listener already running! {self.process.pid}")
                return self
            else:
                logger.warning(f"{method} listener process is not None, "
                               f"but not running in system: {self.process}")

        elif not self.settings:
            logger.warning(f"wallet config not provided")
            return

        cwd = os.getcwd()
        os.chdir(self.config.wallet_data_directory)

        try:
            args = f"./{self.config.binary_name} {subcommand}"
            if method in ['http', 'epicbox']: args += f" -m {method}"
            process = subprocess.Popen(args.split(' '), stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

            # Provide pass as input, not argument (security)
            pass_ = get_secret_value(f"{defaults.PASSWORD_STORAGE_PATH}/{self.config.id}")
            process.communicate(input=pass_, timeout=1)

            logger.info(f">> {method} listener is running [PID: {process.pid}]!")
            self.process = psutil.Process(int(process.pid))

        except subprocess.TimeoutExpired:
            pass

        except Exception as e:
            if 'Only one usage of each socket address' in str(e) \
                or 'Address already in use' in str(e):
                logger.warning(f">> {method} listener already running!")
            else:
                logger.error(f"\n\n{str(e)}\n\n")
        os.chdir(cwd)
        time.sleep(0.3)

        return self
#
#
# class WalletConfig(utils.TOMLConfig):
#     def __init__(self, wallet_dir: str, password: str, **kwargs):
#         self.config_file = os.path.join(wallet_dir, 'epic-wallet.toml')
#
#         if os.path.isfile(self.config_file):
#             super().__init__(self.config_file)
#
#         self.tor = self.settings['tor']
#         self.wallet = self.settings['wallet']
#         self.logging = self.settings['logging']
#         self.password = password
#         self.wallet_dir = wallet_dir
#         self.accounts: list = [Account(id=0, name='default')]
#
#         for key, value in kwargs.items():
#             setattr(self, key, value)
#
#     def __str__(self):
#         return f"WalletConfig({self.wallet_dir})"


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

