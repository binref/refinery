#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from struct import unpack
from pefile import PE, DIRECTORY_ENTRY

from ... import Unit, RefineryPartialResult


class pesig(Unit):
    """
    Extracts the contents of the IMAGE_DIRECTORY_ENTRY_SECURITY entry of a PE file,
    i.e. the digital signatures in DER format.
    """

    _SECDIRID = DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']

    def __init__(self): pass

    def process(self, data: bytearray) -> bytearray:
        pe = PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[self._SECDIRID])
        security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[self._SECDIRID]
        self.log_info(F'signature offset: 0x{security.VirtualAddress:08X}')
        self.log_info(F'signature length: 0x{security.Size:08X}')
        if security.VirtualAddress == 0 or security.Size == 0:
            raise ValueError(F'IMAGE_DIRECTORY_ENTRY_SECURITY ({self._SECDIRID}) is corrupt.')
        sgnoff = security.VirtualAddress + 8
        sgnend = sgnoff + security.Size
        length, revision, certtype = unpack('<IHH', data[sgnoff - 8:sgnoff])
        signature = data[sgnoff:sgnend]

        if len(signature) + 8 != length:
            raise RefineryPartialResult(
                F'Found {len(signature) + 8} bytes of signature, but length should be {length}.',
                partial=signature)

        return signature
