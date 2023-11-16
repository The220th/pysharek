# -*- coding: utf-8 -*-

from .sup import bytes_to_int, int_to_bytes


def print_bytes(bs: bytes):
    res = ""
    for i in bs:
        res += f"{i}_"
    res = res[:-1]
    print(f"\n{res}")




def pand(bs: bytes, n: int) -> bytes:
    _n = len(bs)
    if _n % n != 0:
        res = bs + b'\x00'*(n - _n % n)
    else:
        res = bs
    return res
