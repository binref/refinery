#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pefile import PE, DIRECTORY_ENTRY

from . import HashUnit

IMAGE_DIRECTORY_ENTRY_IMPORT = DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']


class imphash(HashUnit):
    """
    Implements the import hash for PE files.
    """

    def _algorithm(self, data):
        pe = PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[IMAGE_DIRECTORY_ENTRY_IMPORT])
        th = pe.get_imphash()
        if not th:
            raise ValueError('no import directory.')
        return bytes.fromhex(th)
