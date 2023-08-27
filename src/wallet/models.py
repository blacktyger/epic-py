from _decimal import Decimal
from types import NoneType
from typing import Any
import subprocess
import threading
import datetime
import copy
import uuid
import os

from pydantic import BaseModel, Field
import tomlkit
import psutil

from .. import utils


class Account(BaseModel):
    id: int
    path: str
    label: str

    def __repr__(self):
        return f"Account({self.label}, [{self.id}])"


class Transaction(BaseModel):
    id: int
    status: str
    tx_type: str
    tx_slate_id: str
    fee: Decimal
    confirmed: bool
    amount_credited: Decimal
    amount_debited: Decimal
    confirmation_ts: datetime.datetime | None
    creation_ts: datetime.datetime
    kernel_excess: str
    messages: dict
    num_inputs: int
    num_outputs: int
    parent_key_id: str
    payment_proof: str | None
    stored_tx: str | None
    ttl_cutoff_height: int | None
    kernel_lookup_min_height: int

    def __init__(self, **kwargs):
        readable_ints = ['amount_credited', 'amount_debited', 'fee']

        for k, v in copy.copy(kwargs).items():
            if k in readable_ints:
                if isinstance(v, NoneType):
                    kwargs[k] = 0
                else:
                    kwargs[k] = Decimal(v) / Decimal(10**8)

        if 'Cancelled' in kwargs['tx_type']:
            kwargs['status'] = 'Cancelled'
        elif not kwargs['confirmed']:
            kwargs['status'] = 'Pending'
        elif kwargs['confirmed']:
            kwargs['status'] = "Confirmed"
        else:
            kwargs['status'] = 'Unknown'

        super().__init__(**kwargs)

    def get_message(self):
        if self.messages:
            try:
                return self.messages['messages'][0]['message']
            except Exception as e:
                print(e)
                return ''

    def __repr__(self):
        if self.tx_type in ('TxSent', 'TxSentCancelled'):
            amount = self.amount_debited - self.amount_credited - self.fee
            tx_type = 'Sent    '
        elif self.tx_type in ('TxReceived', 'TxReceivedCancelled'):
            amount = self.amount_credited
            tx_type = 'Received'
        else:
            tx_type = 'Mined   '
            amount = self.amount_credited

        return f"Transaction({tx_type} | {self.status} | {str(amount)} | {self.tx_slate_id})"


class Balance(BaseModel):
    amount_awaiting_confirmation: Decimal | None = 0
    amount_awaiting_finalization: Decimal | None = 0
    amount_currently_spendable: Decimal | None = 0
    last_confirmed_height: int | None = 0
    minimum_confirmations: int | None = 1
    amount_immature: Decimal | None = 0
    amount_locked: Decimal | None = 0
    timestamp: datetime.datetime
    outputs: list | None = list()
    total: Decimal | None = 0
    error: str | None = ''

    def __init__(self, **kwargs):
        ignore_fields = ('minimum_confirmations', 'last_confirmed_height', 'error', 'outputs')

        # Change value format to human-readable decimals, i.e. from 100000000 to 1
        for k, v in kwargs.items():
            if k not in ignore_fields:
                try:
                    kwargs[k] = Decimal(v) / Decimal(10 ** 8)
                except:
                    kwargs[k] = Decimal(v)

        kwargs['timestamp'] = datetime.datetime.now()

        super().__init__(**kwargs)

    @property
    def pending(self):
        return self.amount_awaiting_confirmation

    @property
    def to_finalize(self):
        return self.amount_awaiting_finalization

    @property
    def spendable(self):
        return self.amount_currently_spendable

    @property
    def immature(self):
        return self.amount_immature

    @property
    def locked(self):
        return self.amount_locked

    def significant(self):
        return f"Total: {self.total}\n" \
               f"Spendable: {self.spendable}\n" \
               f"To Finalize: {self.to_finalize}\n" \
               f"Pending: {self.pending}\n" \
               f"Locked: {self.locked}"

    def __repr__(self):
        return f"Balance({str(self.total)}, [{self.last_confirmed_height}])"


class Settings(BaseModel):
    tor: dict = {}
    wallet: dict = {}
    logging: dict = {}
    epicbox: dict = {}
    file_path: str

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


class EpicBoxConfig(BaseModel):
    address: str | None = Field(default='')
    prefix: str | None = Field('epicbox')
    domain: str | None = Field(default=utils.defaults.EPICBOX_NODE)
    index: int | None = Field(default=0)
    port: str | None = Field(default=utils.defaults.EPICBOX_PORT)
    full_address: str | None

    def __init__(self, **data: Any):
        super().__init__(**data)
        self.init_config()

    def init_config(self):
        self.full_address = f"{self.address}@{self.domain}"

    def get_short_address(self):
        return f"{self.address[0:4]}...{self.address[-4:]}"

    def __str__(self):
        return f"EpicBox({self.address})"


class Config(BaseModel):
    id: str = str(uuid.uuid4())
    name: str = f'wallet_{id}'
    network: str = 'mainnet'
    epicbox: EpicBoxConfig = None
    password: str = ''
    lock_file: str = ''
    description: str = ''
    node_address: str = ''
    epicbox_address: str = ''
    binary_file_path: str = ''
    created_at_height: int = 0
    tx_files_directory: str = '.'
    wallet_data_directory: str = ''

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        for k, v in kwargs.items():
            if k != 'id':  # Protect id field from overriding
                setattr(self, k, v)

        if not self.wallet_data_directory:
            self.wallet_data_directory = os.path.join(os.getcwd(), self.name)

        if not self.node_address:
            self.node_address = utils.defaults.LOCAL_NODE

    def to_toml(self):
        file_info = f"# EPIC PythonSDK - autogenerated wallet configuration file, do not edit.\n\n"
        file = os.path.join(self.wallet_data_directory, 'config.toml')

        with open(file, "w+") as f:
            f.write(file_info)
            if self.epicbox:
                self.epicbox_address = self.epicbox.full_address
            tomlkit.dump(self.dict(exclude={'epicbox'}), f)

    @staticmethod
    def from_toml(file: str):
        with open(file, "r") as f:
            return Config(**dict(tomlkit.load(f)))


class Listener:
    logger = utils.logger

    def __init__(self, settings: Settings, config: Config, method: str, logger=None, process=None):
        if logger is None:
            logger = utils.logger
        self.logger = logger
        self.config = config
        self.settings = settings
        self.process: psutil.Process = process
        self.method: str = method

    async def run(self, **kwargs):
        flags = None
        password = utils.secrets.get(self.config.password)
        force_run = kwargs.get('force_run', False)  # if true close running listener and run new
        method_flag = f'--method {self.method}'
        listen_port = None

        arguments = f"{self.config.binary_file_path} -p {password} -t {self.config.wallet_data_directory} -c {self.config.wallet_data_directory}"

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
            case _:
                self.logger.error(f'"{self.method}" is not a valid listening method')
                return

        arguments += f" {command}"

        if flags:
            arguments += f" {flags}"

        if listen_port:
            listen_port = self.settings.get(category='wallet', key=listen_port)
            external_process_pid = utils.find_process_by_port(listen_port)

            if external_process_pid not in (None, 0, '0'):
                self.process = psutil.Process(int(external_process_pid))
                self.logger.info(f"{self.method} listener already running! PID: [{self.process.pid}]..")

                if force_run:
                    self.logger.warning(f"force_running = True, closing running listener {self.process.pid}")
                    self.stop()
                else:
                    return self

        if self.process:
            if psutil.pid_exists(self.process.pid):
                self.logger.info(f"{self.method} listener already running [PID: {self.process.pid}]..")
                return self
            else:
                self.logger.warning(f"{self.method} listener process is not None, but not running in system: {self.process}")

        elif not self.settings or not self.config:
            self.logger.warning(f"wallet config and/or settings not provided")
            return

        try:
            process = subprocess.Popen(arguments.split(' '), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

            # if self.method == 'epicbox':
            if kwargs['callback']:
                updater = threading.Thread(target=self.log_monitor, args=(process, kwargs['callback']))
                updater.daemon = True
                self.logger.debug(f">> Starting epicbox listener log monitor..")
                updater.start()

            self.logger.info(f">> {self.method} listener started [PID: {process.pid} | PORT: {listen_port}]..")

            self.process = psutil.Process(int(process.pid))
        except Exception as e:
            if 'Only one usage of each socket address' in str(e) or 'Address already in use' in str(e):
                self.logger.warning(f">> other {self.method} listener already running?")
            else:
                self.logger.error(f"\n\n{str(e)}\n\n")

        return self

    @classmethod
    def log_monitor(cls, process, callback):
        """Run extra thread to keep monitoring process output, and parse important feedback"""
        while True:
            line = process.stdout.readline()

            if 'Broken pipe' in line:
                cls.logger.error(line)
            elif line:
                # cls.logger.warning(line)
                callback(' '.join(line.strip('\n').split(' ')[3:]))

    def stop(self):
        if self.process:
            try:
                self.process.kill()
            except Exception as e:
                self.logger.warning(e)

            self.process = None
            self.logger.info(f"'{self.method}' listener closed")

    def __repr__(self):
        if self.process is not None:
            return f"Listener(Method: '{self.method}', Process: PID[{self.process.pid}] | {self.process.status()})"
        else:
            return f"Listener(Method: '{self.method}', Finished)"