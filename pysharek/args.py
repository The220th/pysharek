# -*- coding: utf-8 -*-

import argparse
from .sup import Global


def create_and_init_parser() -> "argparse.ArgumentParser":
    parser = argparse.ArgumentParser(prog="pysharek",
                                     description="Help to secure send file between two peers.")
    parser.add_argument("file", type=str, nargs=1,
                        help="Path to source/output file/directory")

    parser.add_argument("--dublicate_out_to_file", type=str, default=None, required=False,
                        help="Duplicate program output to file")

    parser.add_argument("--log_file", type=str, default=None, required=False,
                        help="Duplicate program output to file")

    parser.add_argument("--version", action="version", version=f"V{Global.version}",
                        help="Check version of diwork")

    parser.add_argument("--connect", type=str, choices=["server", "client"], required=True,
                        help="Usage as server or client")

    parser.add_argument("--mode", type=str, choices=["send", "receive"], required=True,
                        help="Usage as sender or receiver")

    parser.add_argument("--cipher", type=int, choices=[1, 2], required=False, default=1,
                        help="Choose what cipher will be used. PycaFernet (1) or PycaAES256CBC (2). Default 1")

    parser.add_argument("--ip", type=str, default=None,
                        help="If connect=\"client\", define ip to connect")

    parser.add_argument("--port", type=int, required=True,
                        help="Define port for bind/connect")

    parser.add_argument("--password", type=str, required=True,
                        help="Define password for encryption while transferring. "
                             "Password must be same for the sender and receiver")

    return parser


def common_parse(args: "argparse.Namespace") -> None:
    Global.outfile = args.dublicate_out_to_file
    Global.logfile = args.log_file