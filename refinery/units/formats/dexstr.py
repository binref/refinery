#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units import Unit
from refinery.lib.dex import DexFile


class dexstr(Unit):
    """
    Extract strings from DEX (Dalvik Executable) files.
    """
    def process(self, data):
        dex = DexFile(data)
        for string in dex.read_strings():
            yield string.encode(self.codec)
