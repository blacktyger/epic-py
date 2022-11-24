import subprocess
import os
from typing import Union

import psutil

from ..utils import logger
from .. import utils


# Hide CMD windows while using subprocess
si = subprocess.STARTUPINFO()
si.dwFlags |= subprocess.STARTF_USESHOWWINDOW


class CLIHandler:
    """
    Handler for Epic-Cash server (node) CLI.
    """

    def __init__(self, binary_path: str, settings_path: str = ''):
        """
        :param binary_path: string with path to epic binary
        :param settings_path: string with path to server settings
        """
        self.process: Union[None, psutil.Process] = None
        self.is_running = self._is_node_running()

        self.settings: Union[utils.TOMLConfig, None] = None
        self.binary_path = binary_path

        cwd_ = os.path.split(os.path.abspath(binary_path))[0]
        self.cwd = cwd_ if os.path.isdir(cwd_) else '.'

        print(self.cwd)

        if settings_path:
            self.settings = utils.TOMLConfig(settings_path)
            logger.info('Initialized node CLI handler using existing settings')
        else:
            logger.info('Initialized node CLI handler without settings')

        if self.is_running:
            logger.warning(f'Found node process running, PID: {self.process.pid}')

    def _command(self, **kwargs):
        """Prepare cli command and execute via subprocess.run"""
        cwd = kwargs['cwd'] if 'cwd' in kwargs else self.cwd

        args = [self.binary_path, kwargs['command']]
        args += kwargs['extra_args'] if 'extra_args' in kwargs.keys() else []
        args = [str(arg) for arg in args]

        string_cmd = f'Command: {" ".join(args)}'
        logger.info(string_cmd)

        process = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=cwd)
        return process

    @utils.local_access_only
    def _is_node_running(self):
        for process in psutil.process_iter():
            if process.name() == self.binary_name:
                self.process = process
                return True
        return False

    @utils.local_access_only
    def cli_version(self):
        return self._command(command='--version').stdout

    @utils.local_access_only
    def cli_status(self):
        return self._command(command='client', extra_args=['status']).stdout

    @utils.local_access_only
    def cli_ban_peer(self, address: str):
        return self._command(command='client', extra_args=['ban', '--peer', address]).stdout

    @utils.local_access_only
    def cli_unban_peer(self, address: str):
        return self._command(command='client', extra_args=['unban', '--peer', address]).stdout

    @utils.local_access_only
    def cli_connected_peers(self):
        return self._command(command='client', extra_args=['listconnectedpeers']).stdout

    @utils.local_access_only
    def generate_config(self):
        """Generate a configuration epic-server.toml file in the current directory"""
        return self._command(command='server', extra_args=['config']).stdout

    @utils.local_access_only
    def run_server(self, options=None):
        """
        Run the Epic server in this console
        OPTIONS:
            -a, --api_port <api_port>          Port on which to start the api server
            -c, --config_file <config_file>    Path to epic-server.toml configuration file
            -p, --port <port>                  Port to start the P2P server on
            -s, --seed <seed>                  Override seed node(s) to connect to
            -w, --wallet_url <wallet_url>      The wallet listener to which mining rewards will be sent
        """
        if not options: options = []

        if not self.is_running:
            args = [self.binary_path, 'server'] + options + ['run']
            args = [str(arg) for arg in args]
            self.process = subprocess.Popen(f"{' '.join(args)}", creationflags=subprocess.CREATE_NEW_CONSOLE)
            logger.info(f"Epic-Cash server running, PID: {self.process.pid}")
            return self.process
        else:
            logger.warning(f"server already running, PID: {self.process.pid}")

    @utils.local_access_only
    def stop_server(self):
        """Terminate server process"""
        if self.process:
            logger.info(f"Epic-Cash server terminated, PID: {self.process.pid}")
            self.process.terminate()
            self.process = None
        else:
            logger.info("Server process to terminate not found.")
