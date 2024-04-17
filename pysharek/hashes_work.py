# -*- coding: utf-8 -*-

import hashlib
import os

from alive_progress import alive_bar

from .sup import get_files_list, get_file_size, get_dir_size


def calc_hash_bytes(bs: bytes) -> str:
    return hashlib.sha256(bs).hexdigest()


def calc_hash_str(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def calc_hash_file(path: str) -> str:
    path = os.path.abspath(path)

    block_size = 65536  # 64 kB
    sha = hashlib.sha256()
    with open(path, "rb") as fd:
        file_buffer = fd.read(block_size)
        while len(file_buffer) > 0:
            sha.update(file_buffer)
            file_buffer = fd.read(block_size)
    return sha.hexdigest()


# https://github.com/rsalmei/alive-progress/issues/20
def calc_hash_dir(dir_path: str, if_hierarchy=True) -> str:
    dir_path = os.path.abspath(dir_path)
    files = get_files_list(dir_path)
    files = sorted(files)
    files_rel = [os.path.relpath(file_i, dir_path) for file_i in files]
    sha = hashlib.sha256()
    if if_hierarchy:
        for file_i in files_rel:
            sha.update(file_i.encode("utf-8"))

    dir_size = get_dir_size(dir_path)
    hashes = []
    with alive_bar(dir_size) as bar:
        for file_i in files:
            file_i_size = get_file_size(file_i)
            file_i_hash = calc_hash_file(file_i)
            hashes.append(file_i_hash)
            bar(file_i_size)

    hashes = sorted(hashes)

    for hash_i in hashes:
        sha.update(hash_i.encode("utf-8"))

    return sha.hexdigest()
