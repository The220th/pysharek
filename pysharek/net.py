# -*- coding: utf-8 -*-

import json
import hashlib
import os
import time
from alive_progress import alive_bar

from .sup import bytes_to_int, int_to_bytes, plog, Global, pout
import socket
from .crypto import PycaAES256CBC


def print_bytes(bs: bytes):
    res = ""
    for i in bs:
        res += f"{i}_"
    res = res[:-1]
    print(f"\n{res}")


def send_msg(conn, js: dict, bs: bytes):
    msg_hash_len = 32  # sha256
    js = json.dumps(js).encode("utf-8")
    js_len, bs_len = len(js), len(bs)
    js_len_b, bs_len_b = int_to_bytes(js_len), int_to_bytes(bs_len)
    msg = js_len_b + js + bs_len_b + bs
    msg_hash = hashlib.sha256(msg).digest()
    msg_len_b = int_to_bytes(len(msg) + msg_hash_len)
    msg = msg_len_b + msg + msg_hash

    buff = conn.send(msg)


def send_crypto_msg(conn, js: dict, bs: bytes):
    assert Global.cipher.is_started()

    msg_hash_len = 32  # sha256
    js = json.dumps(js).encode("utf-8")
    js_len, bs_len = len(js), len(bs)
    js_len_b, bs_len_b = int_to_bytes(js_len), int_to_bytes(bs_len)
    msg = js_len_b + js + bs_len_b + bs

    msg = Global.cipher.encrypt(msg)
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


def recv_crypto_msg(conn) -> (dict, bytes):
    assert Global.cipher.is_started()

    msg_hash_len = 32  # sha256
    msg_size = conn.recv(4, socket.MSG_WAITALL)
    msg_size = bytes_to_int(msg_size)
    msg_and_hash = conn.recv(msg_size, socket.MSG_WAITALL)
    msg, msg_hash = msg_and_hash[:-msg_hash_len], msg_and_hash[-msg_hash_len:]
    control_hash = hashlib.sha256(msg).digest()

    msg = Global.cipher.decrypt(msg)

    js_size = bytes_to_int(msg[:4])
    js = msg[4:4+js_size]
    js = json.loads(js.decode("utf-8"))
    bs_size = bytes_to_int(msg[4+js_size:4+js_size+4])
    bs = msg[4+js_size+4:4+js_size+4+bs_size]
    # control_hash = hashlib.sha256(msg[:4+js_size+4+bs_size]).digest()
    if msg_hash != control_hash:
        return None
    else:
        return (js, bs)


def socket_create_and_connect(ip: str, port: int) -> socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while True:
        try:
            sock.connect((ip, port))
        except ConnectionRefusedError:
            wait_time = 3
            plog(f"(socket_create_and_connect) ConnectionRefusedError, waiting {wait_time}")
            time.sleep(wait_time)
            continue
        break
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


def handshake_as_server(sock: socket):
    d, iv = recv_msg(sock)
    if "handshake" not in d or d["handshake"] != "1":
        plog("(handshake_as_server): Cannot handshake 1", 3)
        socket_close(sock)
        exit()
    check = hashlib.sha256("handshake".encode("utf-8") + iv).digest()
    send_msg(sock, {"handshake": "2"}, check)
    d, check2 = recv_msg(sock)
    if "handshake" not in d or d["handshake"] != "3":
        plog("(handshake_as_server): Cannot handshake 2", 3)
        socket_close(sock)
        exit()
    if check2 != b"OK":
        plog("(handshake_as_server): not b\"OK\" msg received", 3)
        socket_close(sock)
        exit()
    iv = hashlib.sha256(iv).digest()[:16]
    Global.cipher.set_iv(iv)


def handshake_as_client(sock: socket):
    iv = os.urandom(16)
    send_msg(sock, {"handshake": "1"}, iv)
    check = hashlib.sha256("handshake".encode("utf-8") + iv).digest()
    d, check2 = recv_msg(sock)
    if "handshake" not in d or d["handshake"] != "2":
        plog("(handshake_as_client): Cannot handshake 1", 3)
        socket_close(sock)
        exit()
    if check != check2:
        plog("(handshake_as_client): hashes does not match!", 3)
        socket_close(sock)
        exit()
    else:
        send_msg(sock, {"handshake": "3"}, b"OK")
    iv = hashlib.sha256(iv).digest()[:16]
    Global.cipher.set_iv(iv)


def test_net_1():
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


def test_net_2():
    import sys
    if sys.argv[1] == "1":
        sock = socket_create_and_connect("127.0.0.1", 8882)
        handshake_as_client(sock)
    else:
        sock = socket_create_and_listen(8882)
        handshake_as_server(sock)

    socket_close(sock)
