# -*- coding: utf-8 -*-

import sys
import os
import io
import json

from .sup import get_files_list, get_file_size, get_file_time


def build_dir_meta(dir_path: str) -> dict:
    dir_path = os.path.abspath(dir_path)
    files = get_files_list(dir_path)
    files = [os.path.relpath(file_i, dir_path) for file_i in files]
    files = sorted(files)

    d = {}
    for file_i in files:
        d[file_i] = {"size": get_file_size(file_i), "time": get_file_time(file_i)}

    return d

