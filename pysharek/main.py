# -*- coding: utf-8 -*-

import os
import sys

base_dir = os.path.dirname(__file__)
sys.path.insert(0, base_dir)


from .sup import *
from .net import *
from .args import *
from .work import work_as_sender, work_as_receiver
from .crypto import PycaAES256CBC, PycaFernet
from . import __version__


def main():
    Global.version = __version__

    parser = create_and_init_parser()
    args = parser.parse_args(sys.argv[1:])
    common_parse(args)
    plog("Begin pysharek", 1)

    if args.cipher == 1:
        Global.cipher = PycaFernet()
    elif args.cipher == 2:
        Global.cipher = PycaAES256CBC()
    else:
        pout("Failed successfully (cipher 1 or cipher 2)")
        exit()

    Global.file_dir = args.file[0]
    if args.mode == "send":
        work_as_sender(args)
    elif args.mode == "receive":
        work_as_receiver(args)
    else:
        pout("Failed successfully (send or receive)")
        exit()

if __name__ == "__main__":
    main()


