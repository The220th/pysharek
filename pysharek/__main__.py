# -*- coding: utf-8 -*-

import os
import sys

base_dir = os.path.dirname(__file__)
sys.path.insert(0, base_dir)

from .hashes_work import calc_hash_dir
from .sup import Global, pout
from .net import *
from .args import *
from .work import work_as_sender, work_as_receiver
from .crypto import PycaAES256CBC


if __name__ == "__main__":
    Global.version = "0.03"
    Global.cipher = PycaAES256CBC()

    parser = create_and_init_parser()
    args = parser.parse_args(sys.argv[1:])
    common_parse(args)

    Global.file_dir = args.file[0]
    if args.mode == "send":
        work_as_sender(args)
    elif args.mode == "receive":
        work_as_receiver(args)
    else:
        pout("Failed successfully (send or receive)")
        exit()


