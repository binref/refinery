#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pefile import PE, PEFormatError
from struct import unpack

from ... import Unit
from ..formats.pe import get_pe_size


class carve_pe(Unit):
    """
    Extracts anything from the input data that looks like a Portable
    Executable (PE) file.
    """
    def process(self, data):
        cursor = 0
        while True:
            p = data.find(B'MZ', cursor)
            if p < cursor: break
            cursor = p + 2
            k, = unpack('H', data[p + 0x3C:p + 0x3E])
            if data[p + k:p + k + 2] != B'PE':
                continue
            try:
                pe = PE(data=data[p:])
            except PEFormatError as err:
                self.log_debug('parsing of PE header at 0x{p:08X} failed:', err)
                continue
            pesize = get_pe_size(pe)
            self.log_info(F'extracted PE file of size 0x{pesize:08X} from 0x{p:08X}')
            yield data[p:p + pesize]
            cursor = pe.OPTIONAL_HEADER.SizeOfHeaders + p
