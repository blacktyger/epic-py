from typing import Any
import subprocess
import uuid
import time
import os

from pydantic import BaseModel, Field
import tomlkit
import psutil

from utils import *
from utils import secret_manager


class Account(BaseModel):
    id: int
    path: str
    label: str

    def __repr__(self):
        return f"Account({self.name}, [{self.id}])"


class Settings(BaseModel):
    file_path: str
    tor: dict = {}
    wallet: dict = {}
    logging: dict = {}
    epicbox: dict = {}

    def __init__(self, **data: Any):
        super().__init__(**data)

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
        if sub_category:
            data_ = getattr(self, category)
            data_[key][sub_category] = value
        else:
            data_ = getattr(self, category)
            data_[key] = value

        setattr(self, category, data_)

        self._save_to_file()


class Config(BaseModel):
    id: str = str(uuid.uuid4())
    name: str = f'wallet_{id}'
    debug: bool = True,
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


class Listener:
    def __init__(self, settings, config, method):
        self.settings: Settings = settings
        self.process: psutil.Process | None = None
        self.config: Config = config
        self.method: str = method

    def run(self, **kwargs):
        flags = None
        password = secret_manager.get_value(self.config.password)
        method_flag = f'--method {self.method}'
        listen_port = None

        arguments = f"./{self.config.binary_name} -p {password}"

        match self.method:
            case 'http':
                listen_port = 'api_listen_port'
                command = 'listen'
                flags = method_flag
            case 'owner_api':
                listen_port = 'owner_api_listen_port'
                command = 'owner_api'
            case 'epicbox':
                command = 'listen'
                flags = method_flag

                if 'interval' in kwargs:
                    interval = kwargs['interval']
                    flags += f" --interval {interval}"
            case _:
                logger.error(f'"{self.method}" is not a valid listening method')
                return

        arguments += f" {command}"
        if flags: arguments += f" {flags}"

        if listen_port:
            listen_port = self.settings.get(category='wallet', key=listen_port)
            external_process_pid = find_process_by_port(listen_port)

            if external_process_pid not in (None, 0, '0'):
                self.process = psutil.Process(int(external_process_pid))
                logger.info(f"{self.method} listener already running! PID: {self.process.pid}]..")
                return self

        if self.process:
            if psutil.pid_exists(self.process.pid):
                logger.info(f"{self.method} listener already running [PID: {self.process.pid}]..")
                return self
            else:
                logger.warning(f"{self.method} listener process is not None, "
                               f"but not running in system: {self.process}")

        elif not self.settings or not self.config:
            logger.warning(f"wallet config not provided")
            return

        # Save current working directory to go back to it when finished
        cwd = os.getcwd()
        os.chdir(self.config.wallet_data_directory)

        try:
            process = subprocess.Popen(arguments.split(' '), text=True, start_new_session=True)
            logger.info(f">> {self.method} listener is running [PID: {process.pid}]..")
            self.process = psutil.Process(int(process.pid))
        except Exception as e:
            if 'Only one usage of each socket address' in str(e) \
                or 'Address already in use' in str(e):
                logger.warning(f">> {self.method} listener already running?")
            else:
                logger.error(f"\n\n{str(e)}\n\n")
        os.chdir(cwd)

        return self

    def __repr__(self):
        return f"Listener(Method: '{self.method}', Process: PID[{self.process.pid}] | {self.process.status()})"

    def stop(self):
        if self.process:
            try: self.process.kill()
            except Exception as e: logger.warning(e)

            self.process = None
            logger.info(f"'{self.method}' listener closed")
        else:
            logger.warning(f"'{self.method}' listener wasn't working")

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
    domain: str | None = Field(default=defaults.EPICBOX_NODE)
    port: str | None = Field(default=defaults.EPICBOX_PORT)
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

