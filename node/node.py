import os

from ..utils.defaults import Node as defaults
from .node_cli import CLIHandler
from .node_http import HTTPHandler
from ..utils import logger
from .. import utils


class ServerNode(HTTPHandler, CLIHandler):
    """
    Class representing Epic-Cash server/node instance with
    various helper functions and API calls
    """
    binary_name = defaults.binary_name
    http_api_version = 'v2'
    supported_versions = ['3.0.0']

    def __init__(self,
                 access: str = 'local',
                 api_url: str = '',
                 api_secret: str = '',
                 binary_path: str = '',
                 settings_path: str = ''
                 ):
        """
        :param access: string, 'local' or 'remote'
        :param api_url: string, address pointing to working node api, i.e. http://127.0.0.1:3413
        :param api_secret: str, path to file or raw secret
        :param binary_path: str, path to epic node binary
        :param settings_path: str, path to settings file
        """

        self._height: int = 0
        self._status: str = ''
        self._online_peers: int = 0
        self._network_height: int = 0

        self._cashed_height: int = 0
        self._cashed_network_height: int = 0

        self.access = access
        self.version: str = ''
        self.connection_status: str = ''

        if access == 'local':
            logger.info('>> Initialize local node..')

            # Check provided binary_path
            if os.path.isfile(binary_path) and utils.check_binary(binary_path):
                binary_path = binary_path

            # Check default binary_path
            elif os.path.isfile(defaults.binary_path) and utils.check_binary(defaults.binary_path):
                binary_path = defaults.binary_path

            # Check in PATH env variable
            elif utils.check_binary(self.binary_name):
                binary_path = self.binary_name

            else:
                raise utils.NodeError('BINARY NOT FOUND')

            self.version = utils.check_binary(binary_path)
            print(self.version)

            if self.version not in self.supported_versions:
                logger.warning(f"binary 'v{self.version}' is not in "
                               f"supported versions: {self.supported_versions}")
                raise utils.NodeError('VERSION NOT SUPPORTED')

            if os.path.isfile(settings_path):
                settings_path = settings_path
            elif os.path.isfile(defaults.settings_path):
                settings_path = defaults.settings_path
            else:
                settings_path = ''

            print(settings_path)
            CLIHandler.__init__(self, binary_path, settings_path)

            # Try to get values from settings
            if api_url: self.api_url = api_url
            else: self.api_url = self.settings.get(category='server', sub_category='', key='api_http_addr')

            if api_secret: self.auth_pass = api_secret
            else: self.auth_pass = self.settings.get(category='server', sub_category='', key='api_secret_path')

            # If settings not provided use default values
            if not self.api_url:
                self.api_url = defaults.api_http_addr
                self.auth_pass = defaults.api_secret_path

            HTTPHandler.__init__(self, url=self._url(), auth_user='epic', auth_pass=utils.parse_secret(self.auth_pass))

        if access == 'remote':

            if utils.is_valid_url(api_url):
                self.api_url = api_url
            else:
                logger.info(f"Provided 'api_url' is not a valid server API url, will try default instead")
                self.api_url = defaults.api_http_addr

            if api_secret: self.auth_pass = api_secret
            else: self.auth_pass = defaults.api_secret_path

            HTTPHandler.__init__(self, url=self.api_url, auth_user='epic',
                                 auth_pass=utils.parse_secret(self.auth_pass))

            if self._public_check_connection():
                if self._private_check_connection():
                    logger.info(f"Access to node with owner rights")
                else:
                    logger.info(f"Access to node with public (foreign) rights")

                logger.info(self.connection_status)
            else:
                raise utils.NodeError("URL")

    @property
    def height(self) -> int:
        self._height = self.get_tip()['height']
        return self._height

    @height.setter
    def height(self, height):
        self._height = height

    @property
    def network_height(self) -> int:
        self._network_height = utils.get_height_from_network()
        return self._network_height

    @property
    def status(self) -> str:
        self._status = self.get_status()['sync_status']
        return self._status

    @status.setter
    def status(self, status):
        self._status = status

    @property
    def online_peers(self):
        self._online_peers = self.get_status()['connections']
        return self._online_peers

    @online_peers.setter
    def online_peers(self, online_peers):
        self._online_peers = online_peers

    def _public_check_connection(self):
        """ Try to connect to node and report its status.
        :return: string, status of connection to the target node
        """

        try:
            # To avoid multiple api calls save values
            self._cashed_height = self.height
            self._cashed_network_height = self.network_height
            self.version = self.get_version()['node_version']

            if self._cashed_network_height and self._cashed_height >= (self._cashed_network_height - 10):
                self.connection_status = f"Connected to synchronized node v{self.version} " \
                                         f"at height {self._cashed_height}."
            else:
                self.connection_status = f"Connected to node v{self.version} " \
                                         f"at height {self._cashed_height} (not synchronized)."
            return True

        except Exception as e:
            self._handle_connection_error(e)
            return False

    def _private_check_connection(self):
        """ Try to connect to node and update status, need access to owner API.
        :return: string, status of connection to the target node
        """
        try:
            status = self.status

            if self._cashed_network_height and status == 'no_sync' and \
                self._cashed_height >= (self._cashed_network_height - 10):

                self.connection_status = f"Connected to node: {self.version} " \
                                         f"at height {self._cashed_height}, " \
                                         f"{self.online_peers} peers."

            elif self._cashed_height and status != 'no_sync':
                behind = self.network_height - self._cashed_height
                self.connection_status = f"Connected to node: {self.version}, " \
                                         f"status: '{status}', {behind} blocks left"

            else:
                self.connection_status = f"Connected to node: {self.version}, " \
                                         f"not synchronised, status: '{status}'."

            return True

        except Exception as e:
            self._handle_connection_error(e)
            return False

    def _handle_connection_error(self, error):
        if '404' in str(error):
            self.connection_status = f"Not connected, is '{self._url()}' a valid node address?"
        elif 'unauthorized' in str(error).lower():
            if self.auth_pass:
                logger.info(f"No authorization for 'owner' methods, check provided 'api_secret'")
        else:
            self.connection_status = f"Not connected, {error}"

    def _url(self) -> str:
        """
        :return: string, formatted and valid API URL
        # http://127.0.0.1:3413/v2
        """
        url = self.api_url.replace('http://', '').replace('https://', '').rstrip('/')
        return f"http://{url}/{self.http_api_version}"

    def get_url(self):
        return self._url()

"""
## Possible Node() class types:
    - as PUBLIC  REMOTE - foreign api exposed
         i.e. open access node (provider) for wallets
         Exposing foreign API is safe for node owner
    - as PRIVATE REMOTE - foreign and owner api exposed
         i.e. private remote access, mining nodes
         Exposing owner api is a risk, security measures advised
    - as PRIVATE LOCAL  - foreign and owner api exposed
         default and most encouraged use-case
         Run safely owner and foreign api on local machine

## Possible Node() class use-cases:
    ### REMOTE (without access to server cli)
        - to connect wallet software (foreign api)
        - to connect mining software (foreign api)
        - to manage server (owner and foreign api)
    ### LOCAL (with access to server cli)
        - fresh installation, no previous files
        - already existing node data with default paths
        - already existing node data with custom paths

## Requirements to run Node() class:
    ### REMOTE - LIMITED ACCESS:
        - http/s address with running node api, default `http://127.0.0.1:3413`
        - by default need basic http authentication with user and password,
          default user: 'epic', password in file: `~/.epic/main/.api_secret`,
          when connecting to the remote server you have to either:
            - ask node owner to provide .api_secret
            - ask node owner to disable basic authentication
          this is true for both owner and foreign API
    ### LOCAL - FULL ACCESS:
        - `epic` node binary file with path saved in the PATH env variable
        - full path to the `epic` node binary file

## Node class initializing steps:
```python
// by default node will try to initialize as 'local'
if access == 'local':
    if binary_path is valid:
        if custom or default `epic-server.toml` is valid:
            settings = Settings('epic-server.toml')
            // ✅ local node fully initialized
        else:
            >> create new `epic-server.toml` file in default path
            settings = Settings('epic-server.toml')
            // ✅ local node successfully initialized
    else:
        >> without access to binary file we change `access` to 'remote'
        access = 'remote'
        // ❔ node will try to initialize as 'remote'

elif access == 'remote':
    if custom or default api_url is valid:
        if not api_secret:
            check_connection()
            if check_connection():
                // ✅ remote node successfully initialized
            else:
                // ❌ need auth 
        else:
            check_connection()
            if failed check_connection():
                // ❌ wrong auth or url 
    else:
        // ❌ provide valid api url
```
"""
