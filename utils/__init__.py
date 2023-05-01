from typing import Union, Any
import subprocess
import functools
import time
import os
import re

from killport import get_processes
import requests

from . import secret_manager as secrets
from .logger_ import get_logger
from .errors import NodeError
from . import defaults

logger = get_logger()


def benchmark(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        stop = time.time()
        logger.warning(f">> BENCHMARK: {func.__name__} took {(stop - start):.4f} seconds")
        return result

    return wrapper


def return_to_cwd(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        cwd = os.getcwd()
        result = func(*args, **kwargs)
        os.chdir(cwd)
        return result

    return wrapper


def response(error: bool = False, message: str = 'success',
             result: Any = None) -> dict:
    return {'error': error, 'message': message, 'result': result}


def parse_uuid(string: str):
    uuid_extract_pattern = "[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}"
    return re.findall(uuid_extract_pattern, string)


def find_process_by_port(port: int):
    result = get_processes(ports=[port])

    if result:
        return result[0].process.pid
    else:
        return None


def find_process_by_name(name):
    """Return process ids found by (partial) name or regex."""
    child = subprocess.Popen(['pgrep', '-f', name], stdout=subprocess.PIPE, shell=False)
    response = child.communicate()[0]
    return [int(pid) for pid in response.split()]


def get_tx_slate_id(slate: str) -> str | None:
    """Extract tx_slate_id UUID from various types of data"""
    pattern = '[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    dashes = True

    if not slate:
        return None

    if isinstance(slate, list):
        slate = slate[0]

    if isinstance(slate, dict):
        # print(slate)
        for k, v in slate.items():
            if re.findall(pattern, k):
                return k

    while dashes:
        if '[null, null]' in slate:
            return None

        slate = slate.replace('\\', '')

        if '\\' in slate:
            continue
        else:
            dashes = False
    try:
        extract = slate.split('tx_slate_id')[1]. \
            split('":"')[1]. \
            split('"')[0]

        match = re.findall(pattern, extract)

        if match:
            match = match[0]
            return match
    except:
        return None


def is_valid_url(url):
    regex = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:(?:[A-Z\d](?:[A-Z\d-]{0,61}[A-Z\d])?\.)+(?:[A-Z]{2,6}\.?|[A-Z\d-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    return re.match(regex, url)


def local_access_only(func):
    """Decorator for cli methods"""

    def wrapper(self, *args, **kwargs):
        if self.access == 'remote':
            logger.warning("'remote' type of node have no access to 'local' methods.")
            return False
        else:
            return func(self, *args, **kwargs)

    return wrapper


def parse_api_response(response: Union[dict, requests.Response]):
    """Handle EPIC API response errors"""

    if isinstance(response, requests.Response):
        if response.status_code not in [200, 201]:
            if response.status_code == 401:
                logger.info("Unauthorized to access API")
            else:
                raise SystemExit(f"Error: {response.status_code}, {response.reason}")
        try:
            response = response.json()
        except ValueError as e:
            raise SystemExit(f"Error while reading api response: '{str(e)}'\n"
                             f"Make sure your auth credentials are valid.")

    if "error" in response:
        raise SystemExit(f'{response["error"]}')

    elif "Err" in response:
        raise SystemExit(f'{response["result"]}')

    elif 'Ok' in response['result']:
        return response['result']['Ok']

    else:
        return response


def check_binary(binary_path: str) -> Union[None, str]:
    """Check if given pat is valid binary, if yes return version of the software"""
    binary_version = subprocess.getoutput(f'{binary_path} --version')
    if "not recognized" in binary_version:
        return None
    else:
        return binary_version.split(' ')[-1]


def get_height_from_network() -> int:
    """
    Get height from official https://explorer.epic.tech
    :return: int, epic-cash network height from explorer
    """
    try:
        return int(requests.get("https://explorer.epic.tech/api?q=getblockcount").json())
    except Exception as e:
        logger.info(str(e))
        return 0


def parse_secret(api_secret: str) -> str:
    """
    Parse .owner_api_secret, input can be path to file or secret itself
    :param api_secret: string, path or secret
    :return: string, secret
    """
    if os.path.isfile(api_secret):
        with open(api_secret, 'r') as f:
            wallet_secret = f.read()
        return wallet_secret
    else:
        return api_secret
