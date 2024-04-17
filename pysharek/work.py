# -*- coding: utf-8 -*-

import sys
import os
import io
import json
import argparse
import hashlib

from .sup import *
from .net import *
from .crypto import PycaAES256CBC
from .hashes_work import calc_hash_file
from .hashes_work import calc_hash_dir
from .sup import get_dirs_needed_for_files


def work_as_sender(args: "argparse.Namespace"):
    # python -m pysharek --mode send --connect server --port 1337
    #                           --password 123 /tmp/123.mp4 --log_file /tmp/log2.txt --log_debug
    plog("I am sender", 1)
    common_block_of_sender_and_receiver(args)
    file = Global.file_dir

    if os.path.isfile(file):
        send_file(file)
    elif os.path.isdir(file):
        send_dir(file)
    elif not os.path.exists(file):
        pout(f"No such file \"{file}\". Exiting")
        Global.sock.close()
        exit()
    else:
        pout(f"Failed successfully (what is file \"{file}\")")
        Global.sock.close()
        exit()


def send_file(file_name: str):
    file = os.path.abspath(file_name)
    plog(f"File (not dir) \"{file}\" will be sended", 1)
    sock = Global.sock
    meta = build_file_meta(file)
    plog(f"meta={meta}", 4)
    plog("Sending meta...", 1)
    send_crypto_msg(sock, meta, b"")
    plog("Meta sended!", 1)
    with open(file, "rb") as fd:
        file_size = meta["file"]["size"]
        plog(f"File size {file_size} bytes", 4)
        readed = 0
        with alive_bar(file_size) as bar:
            block_size = Global.file_size_4_message
            file_buffer = fd.read(block_size)
            plog(f"Readed {len(file_buffer)} bytes", 4)
            bar(len(file_buffer)-1)  # I do not know why need -1?!
            readed += len(file_buffer)
            while len(file_buffer) > 0:
                while True:
                    js_send = {"type": "sending", "file_count": 1, "slice": readed}
                    plog(f"Sendeding: {js_send} + data", 4)
                    send_crypto_msg(sock, js_send, file_buffer)
                    plog(f"Sended", 4)
                    js, bs = recv_crypto_msg(sock)
                    plog(f"Received js={js}", 4)
                    if "type" not in js or js["type"] != "received":
                        pout("Cannot send block. Trying again.")
                    else:
                        break
                file_buffer = fd.read(block_size)
                bar(len(file_buffer))
                readed += len(file_buffer)

    pout(f"Calculating hash...")
    file_hash = calc_hash_file(file)
    pout(f"\"{file_hash}\" is hash of file=\"{file}\"")
    plog(f"Sending file hash", 1)
    hash_msg = {"type": "hash", "file_num": 1, "hash": f"{file_hash}"}
    plog(f"Hash message={hash_msg}", 4)
    send_crypto_msg(sock, hash_msg, b"")
    plog(f"Hash message sended", 4)


def send_dir(dir_name: str):
    dir_name = os.path.abspath(dir_name)
    plog(f"Dir \"{dir_name}\" will be sended", 1)
    meta = build_dir_meta(dir_name)
    files = sorted(meta["files"].keys())
    sock = Global.sock
    plog(f"meta={meta}", 4)
    plog("Sending meta...", 1)
    send_crypto_msg(sock, meta, b"")
    plog("Meta sended!", 1)
    with alive_bar(meta["dir_size"]) as bar:
        for file_i in files:
            # print(file_i)
            # input()
            file = os.path.join(dir_name, file_i)
            with open(file, "rb") as fd:
                file_size = meta["files"][file_i]["size"]
                plog(f"File size {file_size} bytes", 4)
                readed = 0
                block_size = Global.file_size_4_message
                file_buffer = fd.read(block_size)
                bar(len(file_buffer)-1)  # I do not know why need -1?!
                readed += len(file_buffer)
                while len(file_buffer) > 0:
                    while True:
                        js_send = {"type": "sending", "file_count": 1, "slice": readed}
                        plog(f"Sendeding: {js_send} + data", 4)
                        send_crypto_msg(sock, js_send, file_buffer)
                        plog(f"Sended", 4)
                        js, bs = recv_crypto_msg(sock)
                        plog(f"Received js={js}", 4)
                        if "type" not in js or js["type"] != "received":
                            pout("Cannot send block. Trying again.")
                        else:
                            break
                    file_buffer = fd.read(block_size)
                    bar(len(file_buffer))
                    readed += len(file_buffer)

    pout(f"Calculating hash...")
    dir_hash = calc_hash_dir(dir_name, True)
    pout(f"\"{dir_hash}\" is hash of dir \"{dir_name}\"")
    plog(f"Sending file hash", 1)
    hash_msg = {"type": "hash", "hash": f"{dir_hash}"}
    plog(f"Hash message={hash_msg}", 4)
    send_crypto_msg(sock, hash_msg, b"")
    plog(f"Hash message sended", 4)


def work_as_receiver(args: "argparse.Namespace"):
    # python -m pysharek --mode receive --connect client --ip 127.0.0.1 --port 1337
    #                               --password 123 /tmp/333/1234.mp4 --log_file /tmp/log1.txt --log_debug
    plog("I am receiver", 1)
    common_block_of_sender_and_receiver(args)
    file = Global.file_dir

    plog("Receiving meta", 1)
    meta, trash = recv_crypto_msg(Global.sock)
    plog("Received", 1)
    plog(f"meta={meta}", 4)
    if "mode" not in meta:
        pout("Error while receive meta")
        Global.sock.close()
        exit()
    if meta["mode"] == 1:
        receive_file(file, meta)
    elif meta["mode"] == 2:
        receive_dir(file, meta)
    else:
        pout(f"Failed successfully (what is mode \"{meta['mode']}\"?)")


def receive_file(file_name: str, meta: dict):
    plog("File (not dir) will be received", 1)
    sock = Global.sock
    file = os.path.abspath(file_name)
    if os.path.isfile(file):
        pout(f"File \"{file}\" already exists. Delete it? (Y/n) ", endl=False)
        user_in = input()
        plog(f"User enter={user_in}", 4)
        if not (user_in == "" or user_in[0].lower() in ["y", "1"]):
            pout(f"Not delete. Exiting...")
            Global.sock.close()
            exit()
    if os.path.isdir(file):
        pout(f"Tt is planned to receive a file, and this \"{file}\" is a directory. Exiting...")
        Global.sock.close()
        exit()

    file_dir = os.path.dirname(file)
    if not os.path.exists(file_dir):
        plog(f"Making dir: {file_dir}", 4)
        mkdir_with_p(file_dir)

    with open(file_name, "wb") as fd:
        writed = 0
        file_size = meta["file"]["size"]
        plog(f"Receiving file size={file_size}", 1)
        with alive_bar(file_size) as bar:
            while writed != file_size:
                while True:
                    plog("Receiving file block", 4)
                    js, file_buffer = recv_crypto_msg(sock)
                    plog(f"Received file block {len(file_buffer)} bytes, js={js}", 4)
                    if "type" not in js or js["type"] != "sending":
                        pout(f"Cannot receive. Requesting the block again.")
                        send_crypto_msg(sock, {"type": "error_again"}, b"")
                        continue
                    writed += len(file_buffer)
                    if js["slice"] != writed:
                        pout(f"Slice {js['slice']} dont same with writed {writed}. Exiting")
                        Global.sock.close()
                        exit()
                    answer = {"type": "received"}
                    plog(f"Sending answer={answer}", 4)
                    send_crypto_msg(sock, answer, b"")
                    plog(f"Sended", 4)
                    fd.write(file_buffer)
                    fd.flush()
                    bar(len(file_buffer))
                    break
    pout(f"Receiving and calculating hash...")
    js, trash = recv_crypto_msg(sock)
    if "type" not in js or js["type"] != "hash":
        pout(f"Cannot receive hash. Exiting")
        Global.sock.close()
        exit()
    recv_hash = js["hash"]
    pout(f"\"{recv_hash}\" is received hash")
    file_hash = calc_hash_file(file)
    pout(f"\"{file_hash}\" is hash of file=\"{file}\"")
    if recv_hash != file_hash:
        pout(f"{'='*15} HASHES DOES NOT MATCH!!! {'='*15}")
    else:
        pout(f"Hashes matched. All is OK!")


def receive_dir(dir_name: str, meta: dict):
    # TODO: check if dir exists and if this not empty
    dir_name = os.path.abspath(dir_name)
    plog(f"Dir will be received", 1)
    sock = Global.sock
    files = sorted(meta["files"].keys())
    files_4_dirs = [os.path.join(dir_name, file_i) for file_i in files]
    needed_dirs = get_dirs_needed_for_files(files_4_dirs)
    for needed_dir_i in needed_dirs:
        mkdir_with_p(needed_dir_i)
    with alive_bar(meta["dir_size"]) as bar:
        for file_i in files:
            # print(file_i)
            # input()
            file_name = os.path.join(dir_name, file_i)
            with open(file_name, "wb") as fd:
                writed = 0
                file_size = meta["files"][file_i]["size"]
                plog(f"Receiving file size={file_size}", 1)
                while writed != file_size:
                    while True:
                        plog("Receiving file block", 4)
                        js, file_buffer = recv_crypto_msg(sock)
                        plog(f"Received file block {len(file_buffer)} bytes, js={js}", 4)
                        if "type" not in js or js["type"] != "sending":
                            pout(f"Cannot receive. Requesting the block again.")
                            send_crypto_msg(sock, {"type": "error_again"}, b"")
                            continue
                        writed += len(file_buffer)
                        if js["slice"] != writed:
                            pout(f"Slice {js['slice']} dont same with writed {writed}. Exiting")
                            Global.sock.close()
                            exit()
                        answer = {"type": "received"}
                        plog(f"Sending answer={answer}", 4)
                        send_crypto_msg(sock, answer, b"")
                        plog(f"Sended", 4)
                        fd.write(file_buffer)
                        fd.flush()
                        bar(len(file_buffer))
                        break
    pout(f"Receiving and calculating hash...")
    js, trash = recv_crypto_msg(sock)
    if "type" not in js or js["type"] != "hash":
        pout(f"Cannot receive hash. Exiting")
        Global.sock.close()
        exit()
    recv_hash = js["hash"]
    pout(f"\"{recv_hash}\" is received hash")
    dir_hash = calc_hash_dir(dir_name, True)
    pout(f"\"{dir_hash}\" is hash of dir=\"{dir_name}\"")
    if recv_hash != dir_hash:
        pout(f"{'='*15} HASHES DOES NOT MATCH!!! {'='*15}")
    else:
        pout(f"Hashes matched. All is OK!")


def common_block_of_sender_and_receiver(args: "argparse.Namespace"):
    plog(f"Common part achieved", 1)
    sock = init_socks_by_connect_and_do_handshake(args)
    plog(f"Handshaked", 1)
    Global.sock = sock

    Global.cipher.set_password(args.password)
    Global.cipher.start()

    plog(f"Inited cipher in common part", 1)

    challenge_cipher(sock)


def init_socks_by_connect_and_do_handshake(args: "argparse.Namespace") -> socket:
    plog(f"It was as {args.connect}", 1)
    plog(f"Init socker and making handshake", 1)
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
    plog("Start cipher challenge", 1)
    num1 = bytes_to_int(os.urandom(4))
    num2 = bytes_to_int(os.urandom(4))
    num3 = num1+num2
    d = {"num1": num1, "num2": num2, "num3": num3}
    plog(f"Sending formed challenge={d}", 4)
    send_crypto_msg(sock, d, b"")
    plog(f"Sended", 1)

    d, trash = recv_crypto_msg(sock)
    plog(f"Received challenge={d}", 4)
    if "num1" not in d or "num2" not in d or "num3" not in d or d["num1"] + d["num2"] != d["num3"]:
        pout("(challenge_cipher): Cannot challenge")
        socket_close(sock)
        exit()
    plog("Cipher challenged", 1)


def build_dir_meta(dir_path: str) -> dict:
    dir_path = os.path.abspath(dir_path)
    files = get_files_list(dir_path)
    files = [os.path.relpath(file_i, dir_path) for file_i in files]
    files = sorted(files)

    d = {"mode": 2, "files": {}}
    for file_i in files:
        src_file_i = os.path.join(dir_path, file_i)
        d["files"][file_i] = {"size": get_file_size(src_file_i), "time": get_file_time(src_file_i)}

    dir_size = 0
    for file_i in d["files"]:
        dir_size += d["files"][file_i]["size"]
    d["dir_size"] = dir_size

    return d


def build_file_meta(file_name: str) -> dict:
    file_name = os.path.abspath(file_name)
    d = dict({"mode": 1})
    d["file"] = {"size": get_file_size(file_name), "time": get_file_time(file_name)}
    return d
