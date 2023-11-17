# -*- coding: utf-8 -*-

import sys
import os
import io
import json
import argparse
import hashlib

from .sup import get_files_list, get_file_size, get_file_time, pout, Global, bytes_to_int
from .net import *
from .crypto import PycaAES256CBC


def work_as_sender(args: "argparse.Namespace"):
    common_block_of_sender_and_receiver(args)


def work_as_receiver(args: "argparse.Namespace"):
    common_block_of_sender_and_receiver(args)


def common_block_of_sender_and_receiver(args: "argparse.Namespace"):
    sock = init_socks_by_connect_and_do_handshake(args)

    Global.cipher.set_password(args.password)
    Global.cipher.start()

    challenge_cipher(sock)

    socket_close(sock)


def init_socks_by_connect_and_do_handshake(args: "argparse.Namespace") -> socket:
    if args.connect == "server":
        sock = socket_create_and_listen(args.port)
        handshake_as_server(sock)
    elif args.connect == "client":
        if args.ip is None:
            pout("If connect=\"client\", \"--ip\" must be defined")
            exit()
        sock = socket_create_and_connect(args.ip, args.port)
        handshake_as_client(sock)
    else:
        pout("Failed successfully (server or client)")
        exit()
    return sock


def challenge_cipher(sock: socket):
    num1 = bytes_to_int(os.urandom(4))
    num2 = bytes_to_int(os.urandom(4))
    num3 = num1+num2
    d = {"num1": num1, "num2": num2, "num3": num3}
    send_crypto_msg(sock, d, b"")

    d, trash = recv_crypto_msg(sock)
    if num1 not in d or num1 not in d or num1 not in d or d["num1"] + d["num2"] != d["num3"]:
        plog("ERROR (challenge_cipher): Cannot challenge")
        socket_close(sock)
        exit()


def build_dir_meta(dir_path: str) -> dict:
    dir_path = os.path.abspath(dir_path)
    files = get_files_list(dir_path)
    files = [os.path.relpath(file_i, dir_path) for file_i in files]
    files = sorted(files)

    d = {}
    for file_i in files:
        d[file_i] = {"size": get_file_size(file_i), "time": get_file_time(file_i)}

    return d
