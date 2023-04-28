from typing import Union
import json

import requests

from ..utils import logger
from .. import utils
from . import models


class EpicBoxHandler:
    """
    Class to manage epic-box connection and transaction flow.
    """

    def __init__(self, wallet_config: models.WalletConfig):
        self.wallet_config = wallet_config
        self.epicbox: models.EpicBoxConfig
        self._load_cfg()