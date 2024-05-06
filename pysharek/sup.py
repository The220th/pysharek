# -*- coding: utf-8 -*-

import os
import sys
import io
import json
import datetime
import random


class Global:
    version = None
    outfile = None
    logfile = None
    log_debug = None
    yes_always = None
    file_dir = None
    sock: "socket" = None
    cipher: "PycaAES256CBC or PycaFernet" = None
    file_size_4_message = 262144  # 256 KB  # 1048576  # 1 MB
    hash_4_thread = None
    continue_from = None

    priv_key = None
    pub_key = None
    pub_key_2 = None
    shared_key = None


def pout(msg: str, endl=True):
    if not endl:
        pout_low(msg)
    else:
        pout_low(msg + "\n")


def pout_low(msg: str):
    print(msg, end="")
    if Global.outfile is not None:
        with open(Global.outfile, "a", encoding="utf-8") as fd:
            fd.write(msg)
            fd.flush()
    # if Global.logfile is not None:
    #     with open(Global.logfile, "a", encoding="utf-8") as fd:
    #         fd.write(msg)
    #         fd.flush()
    plog(msg, 5)


def plog(s: str, _type: int = 1):
    prefix = "UNKNOWN"
    if _type == 0:
        prefix = ""
    elif _type == 1:
        prefix = "INFO"
    elif _type == 2:
        prefix = "WARNING"
    elif _type == 3:
        prefix = "ERROR"
    elif _type == 4:
        prefix = "DEBUG"
    elif _type == 5:
        prefix = "OUTPUT"
    elif _type == 6:
        prefix = "SLICING"
    if Global.logfile is not None:
        if not Global.log_debug and prefix == "DEBUG":
            return
        else:
            time_str = datetime.datetime.now().strftime("[%y.%m.%d %H:%M:%S.%f]")
            with open(Global.logfile, "a", encoding="utf-8") as fd:
                fd.write(f"{time_str} ({prefix}) {s}\n")
                fd.flush()


def get_files_list(dir_path: str) -> list:
    return [os.path.join(path, name) for path, subdirs, files in os.walk(dir_path) for name in files]


def get_dirs_needed_for_files(files: list) -> list:
    dirs = set()
    for file_i in files:
        dir_i = os.path.dirname(file_i)
        dirs.add(dir_i)
    dirs = sorted(list(dirs))
    dirs = list(set(dirs))
    return dirs


def mkdir_with_p(path: str):
    os.makedirs(path, exist_ok=True)


def get_file_size(file: str) -> int:
    file = os.path.abspath(file)
    return os.path.getsize(file)
    # return os.stat(file).st_size


def get_dir_size(dir_path: str) -> int:
    files = get_files_list(os.path.abspath(dir_path))
    res = 0
    for file_i in files:
        res += get_file_size(file_i)
    return res


def get_file_time(file: str) -> str:
    # time_str = datetime.datetime.now().strftime("[%y.%m.%d %H:%M:%S.%f]")
    unix_time_stamp = os.path.getmtime(file)
    time_str = datetime.datetime.fromtimestamp(unix_time_stamp).strftime("%y.%m.%d %H:%M:%S.%f")
    return time_str


def write_json(d: dict, path: str):
    s = json.dumps(d)
    with open(path, "w", encoding="utf-8") as fd:
        fd.write(s)


def read_json(path: str) -> dict:
    path = os.path.abspath(path)
    with open(path, "r", encoding="utf-8") as fd:
        s = fd.read()
    return json.loads(s)


def int_to_bytes(a: int) -> bytes:
    if a < 0 or a > 4294967295:
        raise ValueError(f"int_to_bytes: number {a} more than 2**32-1 or less zero. ")
    return a.to_bytes(4, "big")


def bytes_to_int(bs: bytes) -> int:
    res = int.from_bytes(bs, "big")
    if res < 0 or res > 4294967295:
        raise ValueError(f"bytes_to_int: number {res} more than 2**32-1 or less zero from bytes: \"{bs}\". ")
    return res


def utf8_to_bytes(s: str) -> bytes:
    return s.encode("utf-8")


def bytes_to_utf8(bs: bytes) -> str:
    return str(bs, "utf-8")


def get_random_string(_lenght : int = 20) -> str:
    import string
    S = ''.join(random.choices(string.ascii_uppercase + string.digits, k=_lenght))
    return S


def get_nice_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024*1024:
        devider = 1024
        return f"{round(size_bytes / devider, 3)} KB"
    elif size_bytes < 1024*1024*1024:
        devider = 1024*1024
        return f"{round(size_bytes / devider, 3)} MB"
    elif size_bytes < 1024*1024*1024*1024:
        devider = 1024*1024*1024
        return f"{round(size_bytes / devider, 3)} GB"
    else:
        devider = 1024*1024*1024*1024
        return f"{round(size_bytes / devider, 3)} TB"
