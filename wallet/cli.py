import psutil

import subprocess
import time
import os

from . import models
from .. import utils
from ..utils import logger


class CLIHandler:
    """
    Epic-Cash cli-wallet handler with bindings for RUST library.
    """
    def __init__(self, config: models.WalletConfig):
        self.foreign_api_process: psutil.Process | None = None
        self.owner_api_process: psutil.Process | None = None
        self.config = config

    def run_owner_api(self):
        owner_port = self.config.wallet['owner_api_listen_port']
        external_process_pid = utils.find_process_by_port(owner_port)

        if self.owner_api_process:
            if psutil.pid_exists(self.owner_api_process.pid):
                logger.warning(f"owner_api already running! {self.owner_api_process.pid}")
                return
            else:
                logger.warning(f"instance owner_api process is not None, "
                               f"but not running in system \n{self.owner_api_process}")

        elif external_process_pid not in (None, 0, '0'):
            self.owner_api_process = psutil.Process(int(external_process_pid))
            logger.warning(f"owner_api already running! {self.owner_api_process.pid}")
            return

        elif not self.config:
            logger.warning(f"no wallet config provided")
            return

        cwd = os.getcwd()
        os.chdir(self.config.wallet_dir)

        try:
            logger.info(f">> starting owner_api {self.config.wallet_dir}")
            args = ['./epic-wallet', 'owner_api']

            # Add 'enter' to password and encode to bytes
            pass_ = f"{self.config.password}\n".encode()

            self.owner_api_process = subprocess.Popen(args, stdin=subprocess.PIPE)

            # Provide pass as input, not argument (security)
            self.owner_api_process.communicate(input=pass_, timeout=1)

            logger.info(f">> owner_api is running [PID: {self.owner_api_process.pid}]!")

        except subprocess.TimeoutExpired:
            pass

        except Exception as e:
            if 'Only one usage of each socket address' in str(e) \
                or 'Address already in use' in str(e):
                logger.warning(f">> owner_api already running!")
            else:
                logger.error(f"\n\n{str(e)}\n\n")
                raise SystemExit(f">> owner_api error, {e}") from None

        os.chdir(cwd)
        time.sleep(0.3)

    def run_foreign_api(self):
        foreign_port = self.config.wallet['api_listen_port']
        external_process_pid = utils.find_process_by_port(foreign_port)

        if self.foreign_api_process:
            if psutil.pid_exists(self.foreign_api_process.pid):
                logger.warning(f"foreign_api already running! {self.foreign_api_process.pid}")
                return
            else:
                logger.warning(f"instance foreign_api process is not None, "
                               f"but not running in system \n{self.foreign_api_process}")

        elif external_process_pid not in (None, 0, '0'):
            self.foreign_api_process = psutil.Process(int(external_process_pid))
            logger.warning(f"foreign_api already running! {self.foreign_api_process.pid}")
            return

        elif not self.config:
            logger.warning(f"no wallet config provided")
            return

        cwd = os.getcwd()
        os.chdir(self.config.wallet_dir)

        try:
            logger.info(f">> running foreign_api {self.config.wallet_dir}")
            args = ['./epic-wallet', 'listen']

            # Add 'enter' to password and encode to bytes
            pass_ = f"{self.config.password}\n".encode()

            self.foreign_api_process = subprocess.Popen(args, stdin=subprocess.PIPE)

            # Provide pass as input, not argument (security)
            self.foreign_api_process.communicate(input=pass_, timeout=1)

            logger.info(f">> foreign_api running [PID: {self.foreign_api_process.pid}]!")
            time.sleep(0.3)

        except subprocess.TimeoutExpired:
            pass

        except Exception as e:
            if 'Only one usage of each socket address' in e:
                logger.warning(f">> foreign_api already running!")
            else:
                logger.error(f">> foreign_api error, {e}")
                self.stop_foreign_api()

        os.chdir(cwd)
        time.sleep(0.5)

    def stop_owner_api(self):
        if self.owner_api_process:
            try: self.owner_api_process.kill()
            except Exception as e: logger.warning(e)

            self.owner_api_process = None
            self._encryption_key = None
            self._token = None
            logger.info(f">> owner_api closed, encryption_key deleted")
            return

        logger.warning(f">> owner_api wasn't working")

    def stop_foreign_api(self):
        if self.foreign_api_process:
            try: self.foreign_api_process.kill()
            except Exception as e: logger.warning(e)

            self.foreign_api_process = None
            logger.info(f">> foreign_api closed")
            return

        logger.warning(f">> foreign_api wasn't working")
