#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Implements hash algorithms of short length, commonly used as checksums.
"""
import zlib

from refinery.units.crypto.hash import HashUnit


class crc32(HashUnit):
    """
    Returns the CRC32 hash of the input data.
    """
    def _algorithm(self, data: bytes) -> bytes:
        return zlib.crc32(data).to_bytes(4, 'big')


class adler32(HashUnit):
    """
    Returns the Adler32 hash of the input data.
    """
    def _algorithm(self, data: bytes) -> bytes:
        return zlib.adler32(data).to_bytes(4, 'big')


class djb2(HashUnit):
    """
    Computes the DJB2 hash of the input data.
    """
    def _algorithm(self, data: bytes) -> bytes:
        h = 5381
        for b in data:
            h = ((h << 5) + h + b) & 0xFFFFFFFF
        return h.to_bytes(4, 'big')
