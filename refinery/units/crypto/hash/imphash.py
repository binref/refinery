#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import lief

from refinery.units.crypto.hash import HashUnit
from refinery.lib.structures import MemoryFile


class imphash(HashUnit):
    """
    Implements the import hash for PE files.
    """

    def _algorithm(self, data):
        pe = lief.PE.parse(MemoryFile(data))
        th = lief.PE.get_imphash(pe, lief.PE.IMPHASH_MODE.PEFILE)
        return bytes.fromhex(th)
