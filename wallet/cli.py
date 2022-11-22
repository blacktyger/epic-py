import psutil

import subprocess
import platform
import time
import os

from . import models
from epicpy import utils


class CLIHandler:
    """
    Epic-Cash cli-wallet handler with bindings for RUST library.
    """
    def __init__(self, wallet_dir: str, password: str):
        self.wallet_dir = wallet_dir
        self.password = password

        self.foreign_api_process: psutil.Process | None = None
        self.owner_api_process: psutil.Process | None = None
        self.epicbox: models.EpicBoxConfig | None = None
        self.config: models.WalletConfig | None = None

        self._load_config()

    def _load_config(self, wallet_dir: str = None):
        """load wallet config from *.toml file"""
        if not wallet_dir: wallet_dir = self.wallet_dir
        self.config = models.WalletConfig(wallet_dir, self.password)

    def run_owner_api(self):
        owner_port = self.config.wallet['owner_api_listen_port']
        external_process_pid = utils.find_process_by_port(owner_port)

        if self.owner_api_process:
            print(f"owner_api already running! {self.owner_api_process.pid}")
            return
        elif external_process_pid:
            self.owner_api_process = psutil.Process(int(external_process_pid))
            print(f"owner_api already running! {self.owner_api_process.pid}")
            return
        elif not self.config:
            print(f"no wallet config provided")
            return

        cwd = os.getcwd()
        os.chdir(self.config.wallet_dir)

        try:
            print(f"running owner_api {self.wallet_dir}")
            args = ['./epic-wallet', '-p', self.password, 'owner_api']
            self.owner_api_process = subprocess.Popen(f"{' '.join(args)}")
            print(f">> owner_api running [{self.owner_api_process.pid}]!")

        except Exception as e:
            if 'Only one usage of each socket address' in e:
                print(f"owner_api already running!")
            else:
                print(f">> owner_api error, {e}")
                self.stop_owner_api()

        os.chdir(cwd)
        time.sleep(0.5)

    def run_foreign_api(self):
        foreign_port = self.config.wallet['api_listen_port']
        external_process_pid = utils.find_process_by_port(foreign_port)

        if self.foreign_api_process:
            print(f"foreign_api already running! {self.foreign_api_process.pid}")
            return
        elif external_process_pid:
            self.foreign_api_process = psutil.Process(int(external_process_pid))
            print(f"foreign_api already running! {self.foreign_api_process.pid}")
            return
        elif not self.config:
            print(f"no wallet config provided")
            return

        cwd = os.getcwd()
        os.chdir(self.wallet_dir)

        try:
            print(f">> running foreign_api {self.wallet_dir}")
            args = ['./epic-wallet', '-p', self.password, 'listen']
            self.foreign_api_process = subprocess.Popen(f"{' '.join(args)}")
            time.sleep(0.3)
            print(f">> foreign_api running [{self.foreign_api_process.pid}]!")

        except Exception as e:
            if 'Only one usage of each socket address' in e:
                print(f">> foreign_api already running!")
            else:
                print(f">> foreign_api error, {e}")
                self.stop_foreign_api()

        os.chdir(cwd)
        time.sleep(0.5)

    def stop_owner_api(self):
        if self.owner_api_process:
            self.owner_api_process.kill()
            self._encryption_key = self._token = self.owner_api_process = None
            print(f">> owner_api closed, encryption_key deleted")
            return
        print(f">> owner_api wasn't working")

    def stop_foreign_api(self):
        if self.foreign_api_process:
            self.foreign_api_process.kill()
            self.foreign_api_process = None
            print(f">> foreign_api closed")
            return
        print(f">> foreign_api wasn't working")
