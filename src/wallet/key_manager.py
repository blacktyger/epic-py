from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization
from hashlib import pbkdf2_hmac
import mnemonic

from typing import Union
import binascii
import time
import json
import os


class KeyManager:
    """
    Epic-Cash Wallet cryptography manager:

    create() -> Create completely new epic-wallet instance
    from_bytes() -> Initialize epic-wallet from seed (bytes)
    from_mnemonic() -> Initialize epic-wallet from mnemonic seed-phrase (str)
    from_encrypted_seed() -> Initialize epic-wallet from previously encrypted seed (dict)
    seed_as_str() -> Return wallet seed as string
    """

    SEED_FILE_NAME = 'wallet.seed'
    EPIC_VERSION: float = 3.0
    ITERATIONS: int = 100
    U_SIZE: int = 32

    info: str = None
    seed: bytes = None
    mnemonics: str = None
    public_key: bytes = None
    encrypted_seed_data: dict = None

    def __init__(self, password: str = None,
                 seed: Union[bytes, str] = None,
                 mnemonics: Union[str, list] = None,
                 encrypted_seed: Union[dict, str] = None,
                 *args, **kwargs
                 ):

        if seed:
            if self.from_seed(seed=seed):
                print(f'Successful wallet initialization from seed!')

        elif mnemonics:
            if self.from_mnemonic(mnemonics=mnemonics):
                print(f'Successful wallet initialization from mnemonics!')

        elif encrypted_seed:
            if self.from_encrypted_seed(password=password, encrypted_seed=encrypted_seed):
                print(f'Successful wallet initialization from encrypted seed!')

        else:
            pass
        #     if password:
        #         if self.new(password=password):
        #             print(f'Successful new wallet initialization!')
        #
        # self._info()

    @staticmethod
    def _valid_mnemonics(mnemonics):
        """
        Validation of mnemonics input
        """
        return mnemonic.Mnemonic(language='english').check(mnemonics) \
               and (len(mnemonics.split(' ')) == 12
                    or len(mnemonics.split(' ')) == 24)

    @staticmethod
    def _str_to_bytes(data: str) -> bytes:
        """
        Get str, unhexlify and return bytes
        """
        return binascii.unhexlify(data)

    @staticmethod
    def _bytes_to_str(data: bytes) -> str:
        """
        Get bytes hexlify them and return utf-8 decoded string
        """
        return binascii.hexlify(data).decode('utf-8')

    def _generate_key(self, password: str, salt: bytes):
        """
        Generate HMAC512 Key, needed for wallet seed encryption
        :param password: str
        :param salt: bytes
        :return: bytes, Key
        """
        if isinstance(password, str):
            password = password.encode('utf-8')

        return pbkdf2_hmac("sha512", password,
                           salt, self.ITERATIONS, self.U_SIZE)

    def _encrypted_seed_to_file(self, password: str, path: str) -> None:
        """
        Save encrypted seed data to wallet seed file (JSON)
        :param path: str, directory and file name for wallet seed file
        """
        try:
            self._encrypt_seed(password=password)
        except Exception:
            print("ERROR: can not create wallet seed file")
            return

        with open(path, 'w') as file:
            json.dump(self.encrypted_seed_data, file, indent=2)

    def _decrypt_seed(self, password: str, data: dict) -> [bytes, None]:
        """
        Decrypt encrypted seed data
        :param password: str,
        :param data: dict, keys: encrypted_seed, nonce, salt
        :return: bytes, decrypted seed
        """
        # Validate data dict
        if not isinstance(data, dict) or len(data) < 3:
            raise Exception('Invalid data to decrypt wallet seed')

        # Check against not provided password (None is different than '')
        if password is None:
            return

        # Parse data dict from strings to bytes
        salt = self._str_to_bytes(data['salt'])
        nonce = self._str_to_bytes(data['nonce'])
        encrypted_seed = self._str_to_bytes(data['encrypted_seed'])

        try:
            # Decrypt seed with generated key and given nonce
            enc_key = self._generate_key(password, salt)
            cypher = ChaCha20Poly1305(enc_key)
            decrypted_seed = cypher.decrypt(nonce, encrypted_seed, associated_data=None)

        except Exception as e:
            print(e)
            return

        return decrypted_seed

    def _encrypt_seed(self, password: str) -> dict:
        """
        Generate encrypted seed and return it with nonce and salt
        :param password: str,
        :return: dict, encrypted seed, nonce and salt
        """
        # Generate random bytes for nonce and salt
        nonce = os.urandom(12)
        salt = os.urandom(8)

        # Generate PrivateKey
        enc_key = self._generate_key(password, salt)

        # Encrypt seed with generated PrivateKey and nonce
        cypher = ChaCha20Poly1305(enc_key)
        encrypted_seed = cypher.encrypt(nonce, self.seed, associated_data=None)

        # Prepare data used later to decrypt seed
        self.encrypted_seed_data = {
            "encrypted_seed": self._bytes_to_str(encrypted_seed),
            "salt": self._bytes_to_str(salt),
            "nonce": self._bytes_to_str(nonce)
            }

        return self.encrypted_seed_data

    def _mnemonic_from_seed(self) -> None:
        """
        Generate mnemonics from seed
        """
        mnemonic_obj = mnemonic.Mnemonic("english")
        self.mnemonics = mnemonic_obj.to_mnemonic(self.seed)

    def _public_key_from_seed(self) -> None:
        """
        Generate key pair from seed and return PublicKey
        """
        key_pair = Ed25519PrivateKey.from_private_bytes(self.seed)
        self.public_key = key_pair.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
            )

    def _private_key_from_seed(self) -> Ed25519PrivateKey:
        """
        Generate key pair from seed and return PublicKey
        """
        key_pair = Ed25519PrivateKey.from_private_bytes(self.seed)
        return key_pair
        # self.public_key = key_pair.public_key().public_bytes(
        #     encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        #     )

    def _info(self) -> None:
        """
        Generate wallet summary string
        """
        title = f"\n// --- Epic-Cash Wallet Summary --- \\\\"
        footer = f"// ------- End Wallet Summary ------- \\\\\n"

        try:
            pretty_mnemonics = f"{' '.join(self.mnemonics.split(' ')[:11])}\n" \
                               f"{' '.join(self.mnemonics.split(' ')[11:])}"

            seed = f"Seed (PrivateKey): {self.seed_as_str()}"
            mnemonics = f"Mnemonics: {pretty_mnemonics}"
            public_key = f"PublicKey: {self.public_key_as_str()}"

            self.info = '\n'.join([title, seed, public_key, mnemonics, footer])

        except Exception:
            no_seed = f"WALLET NOT INITIALIZED\n"
            self.info = '\n'.join([title, no_seed, footer])

    def to_dict(self, json_: bool = False) -> Union[dict, str]:
        """
        Serialize instance to python dict
        :param json_: bool, if True return JSON string
        :return:
        """
        data = {
            'seed': self.seed_as_str(),
            'mnemonics': self.mnemonics,
            'public_key': self.public_key_as_str(),
            'encrypted_seed_data': self.encrypted_seed_data
            }

        if json_:
            data = json.dumps(data)

        return data

    def seed_as_str(self) -> str:
        """
        :return: str, seed bytes as string
        """
        return self._bytes_to_str(self.seed)

    def public_key_as_str(self) -> str:
        """
        :return: str, PublicKey byte data as string
        """
        return self._bytes_to_str(self.public_key)

    def new(self, password: str):
        """
        Generate new seed and create new wallet instance
        :param password: string, to encrypt seed
        :return: wallet instance
        """
        try:
            seed = os.urandom(self.U_SIZE)
            self.from_seed(seed)
            self._encrypt_seed(password=password)
        except Exception as e:
            print(e)
            return

        return self

    def from_seed(self, seed: Union[bytes, str]):
        """
        Initialize new epic-wallet instance from seed (random_bytes, 32)
        :param seed: bytes or str representation of 32 random bytes
        :return: wallet instance
        """
        if isinstance(seed, str):
            try:
                seed = binascii.unhexlify(seed)
            except Exception as e:
                print(f"ERROR: Invalid seed\n{e}")
                return
        try:
            self.seed = seed
            self._mnemonic_from_seed()
            self._public_key_from_seed()

        except Exception:
            return

        self._info()
        return self

    def from_encrypted_seed(self, password: str, encrypted_seed: Union[dict, str]):
        """
        Initialize new epic-wallet instance from previously encrypted seed
        Provide full path to wallet seed file or valid dict with data
        :param password: string, must be the same as one when encryption was done ('' blank is possible)
        :param encrypted_seed: str if path to file, dict if python object
        :return: wallet instance
        """

        # Handle no password
        if password is None:
            print(f'ERROR: Provide encryption password')

        # Handle if provided path to seed file
        if isinstance(encrypted_seed, str):
            if os.path.isfile(encrypted_seed):
                try:
                    encrypted_seed = json.load(open(encrypted_seed, 'r'))
                except Exception as e:
                    print(f'ERROR: Invalid wallet seed file\n{encrypted_seed}\n{e}')
                    return
            else:
                print(f'ERROR: {encrypted_seed} is an invalid path or wallet seed file')
                return

        # Validate that data is dictionary instance
        if isinstance(encrypted_seed, dict):
            seed = self._decrypt_seed(password=password, data=encrypted_seed)

            if seed:
                self.from_seed(seed)
                return self
            else:
                print(f'ERROR: Wrong encryption password?')
        else:
            print(f'ERROR: {encrypted_seed} is not valid encrypted seed file data')

    def from_mnemonic(self, mnemonics: Union[str, list]):
        """
        Create new wallet instance from mnemonic seed-phrase
        :param mnemonics: str or list, 12 or 14 words
        :return: wallet instance
        """
        if isinstance(mnemonics, list):
            mnemonics = ' '.join(mnemonics)

        if not self._valid_mnemonics(mnemonics):
            print('Invalid mnemonics')
            return

        mnemonic_obj = mnemonic.Mnemonic("english")
        seed = bytes(mnemonic_obj.to_entropy(mnemonics))
        self.from_seed(seed)

        return self

    def save_to_file(self, password: str, path: str = None):
        """
        Save wallet encrypted seed to file (JSON format)
        :param password: str, to encrypt the wallet seed
        :param path: str, optional path to wallet encrypted seed file
        """
        # Handle no wallet seed
        if not self.seed:
            print('ERROR: Wallet is not initialized (no seed)')
            return

        # Set current working directory as path if not provided
        if not path:
            path = os.getcwd()

        # Handle case with and without file name in path
        if not path.endswith(self.SEED_FILE_NAME):
            file_path = os.path.join(path, self.SEED_FILE_NAME)
        else:
            file_path = path

        # Handle existing 'wallet.seed' file and make backup
        if os.path.isfile(file_path):
            print('Wallet seed file already exist in this directory, making backup..')

            # Prepare path, file name and make backup
            backup_file_name = f"backup_{int(time.time())}_{self.SEED_FILE_NAME}"
            backup_path = os.path.join(path, backup_file_name)
            os.rename(file_path, backup_path)
            print(f'"{self.SEED_FILE_NAME}" renamed to: "{backup_file_name}"')

        # Save encrypted seed dict to file in JSON format
        self._encrypted_seed_to_file(password=password, path=file_path)
        print(f"Wallet seed encrypted and saved in: '{self.SEED_FILE_NAME}' file.")
