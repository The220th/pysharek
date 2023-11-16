# -*- coding: utf-8 -*-

import json
import hashlib

from .sup import bytes_to_int, int_to_bytes, plog, Global
import socket


def print_bytes(bs: bytes):
    res = ""
    for i in bs:
        res += f"{i}_"
    res = res[:-1]
    print(f"\n{res}")


def send_msg(conn, js: dict, bs: bytes):
    msg_hash_len = 32  # sha256
    # buff_size = Global.message_file_size
    js = json.dumps(js).encode("utf-8")
    js_len, bs_len = len(js), len(bs)
    js_len_b, bs_len_b = int_to_bytes(js_len), int_to_bytes(bs_len)
    msg = js_len_b + js + bs_len_b + bs
    msg_hash = hashlib.sha256(msg).digest()
    msg_len_b = int_to_bytes(len(msg) + msg_hash_len)
    msg = msg_len_b + msg + msg_hash

    buff = conn.send(msg)


def recv_msg(conn) -> (dict, bytes):
    msg_hash_len = 32  # sha256
    msg_size = conn.recv(4, socket.MSG_WAITALL)
    msg_size = bytes_to_int(msg_size)
    msg = conn.recv(msg_size, socket.MSG_WAITALL)
    js_size = bytes_to_int(msg[:4])
    js = msg[4:4+js_size]
    js = json.loads(js.decode("utf-8"))
    bs_size = bytes_to_int(msg[4+js_size:4+js_size+4])
    bs = msg[4+js_size+4:4+js_size+4+bs_size]
    msg_hash = msg[4+js_size+4+bs_size:]
    control_hash = hashlib.sha256(msg[:4+js_size+4+bs_size]).digest()
    if msg_hash != control_hash:
        return None
    else:
        return (js, bs)


def socket_create_and_connect(ip: str, port: int) -> socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))
    return sock


def socket_create_and_listen(port: int) -> socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("", port))
    sock.listen(1)
    conn, info = sock.accept()
    return conn


def socket_close(sock: socket):
    sock.close()


def pand(bs: bytes, n: int) -> bytes:
    _n = len(bs)
    if _n % n != 0:
        res = bs + b'\x00'*(n - _n % n)
    else:
        res = bs
    return res


def test_net():
    import sys
    if len(sys.argv) == 2:
        file = sys.argv[1]
        sock = socket_create_and_connect("127.0.0.1", 8881)
        with open(file, "rb") as fd:
            bs = fd.read()
        send_msg(sock, {"msg": "hello"}, bs)
    else:
        sock = socket_create_and_listen(8881)
        js, bs = recv_msg(sock)
        print(js)
        with open("/tmp/test_file.bin", "wb") as fd:
            fd.write(bs)
            fd.flush()

    socket_close(sock)
