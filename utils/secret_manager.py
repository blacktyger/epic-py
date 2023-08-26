import logging
import os

import gnupg
import passpy

logging.getLogger('gnupg').setLevel(60)

"""
BEFORE USING THIS SCRIPT:
- sudo apt-get install gnupg
- gpg --gen-key
- pass init <gpg-id>
"""

os.environ["PYPASS_GPG_BIN"] = "/usr/bin/gpg2"

gpg = gnupg.GPG()
store = passpy.Store(gpg_bin=os.environ["PYPASS_GPG_BIN"])

if not gpg.list_keys(True):
    raise SystemExit("No gpg key, please generate those first with: \n"
                     "gpg --gen-key\n")

key = gpg.list_keys(True)[0]

try:
    store.init_store(gpg_ids=str(key))
    print(f'Password store initialized for {str(key)}')
except OSError:
    pass


def get(path: str):
    """Return value stored with `pass` manager"""
    # return store.get_key(path=path).strip()
    with open(os.path.join(path, f'.secret'), 'r') as file:
        return file.read()


def set(value, path: str):
    """Sety new key:value stored with `pass` manager"""
    # print(path, value)
    # return store.set_key(path=path, key_data=value, force=False)
    with open(os.path.join(path, f'.secret'), 'w') as file:
        file.write(value)

    return path
