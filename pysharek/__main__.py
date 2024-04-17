# -*- coding: utf-8 -*-

# pip3 install build
# python3 -m build
# python3 -m pip install --upgrade twine
# python3 -m twine upload --repository testpypi dist/*
# pip3 install pysharek --no-deps --index-url https://test.pypi.org/simple

import os
import sys

base_dir = os.path.dirname(__file__)
sys.path.insert(0, base_dir)


from .main import main


if __name__ == "__main__":
    main()
