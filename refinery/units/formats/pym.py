#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units import Unit

import importlib
import marshal


class pym(Unit):
    """
    Converts Python-Marshaled code objects to the PYC (Python Bytecode) format. If it is an
    older Python version, you can use the `refinery.pyc` unit to then decompile the code, but
    for more recent versions a separate Python decompiler will be required.

    WARNING: This unit will invoke the `marshal.loads` function, which may be unsafe. Please
    refer to the official Python documentation for more details.
    """

    def process(self, data):
        # https://stackoverflow.com/a/73454818
        return importlib._bootstrap_external._code_to_timestamp_pyc(marshal.loads(data))
