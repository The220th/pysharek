# -*- coding: utf-8 -*-

import os
import sys

base_dir = os.path.dirname(__file__)
sys.path.insert(0, base_dir)

from .hashes_work import calc_hash_dir
from .sup import Global
from .net import *


if __name__ == "__main__":
    Global.version = "0.03"
    test_net_2()



