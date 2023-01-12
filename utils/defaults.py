import platform
from pathlib import Path


if platform.system() == 'Windows':
    bin_ext = '.exe'
else:
    bin_ext = ''


chain = 'main'
home_dir = str(Path.home())
node_secret = '.api_secret'
node_api_port = 3413

wallet_secret = '.owner_api_secret'
wallet_api_port = 3415
wallet_owner_port = 3420

class Node:
    api_addr = '127.0.0.1'
    binary_name = f"epic{bin_ext}"
    top_dir_path = f"{home_dir}\\.epic\\{chain}"
    settings_path = f"{top_dir_path}\\epic-server.toml"
    binary_path = f"{top_dir_path}\\{binary_name}"
    api_http_addr = f"http://{api_addr}:{node_api_port}"
    api_secret_path = f"{top_dir_path}\\{node_secret}"


class Wallet:
    api_addr = '127.0.0.1'
    binary_name = f"epic-wallet{bin_ext}"
    top_dir_path = f"{home_dir}\\.epic\\{chain}"
    binary_path = f"{top_dir_path}\\{binary_name}"
    settings_path = f"{top_dir_path}\\epic-wallet.toml"
    api_http_addr = f"{api_addr}:{wallet_api_port}"
    owner_http_addr = f"{api_addr}:{wallet_owner_port}"
    owner_secret_path = f"{top_dir_path}\\{wallet_secret}"
