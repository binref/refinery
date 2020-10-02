#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Implements hash algorithms of short length, commonly used as checksums.
"""
import zlib
import struct

from . import HashUnit


class crc32(HashUnit):
    """
    Returns the CRC32 Hash of the input data.
    """
    @classmethod
    def _algorithm(cls, data: bytes) -> bytes:
        return struct.pack('>I', zlib.crc32(data))


class adler32(HashUnit):
    """
    Returns the Adler32 Hash of the input data.
    """
    @classmethod
    def _algorithm(cls, data: bytes) -> bytes:
        return struct.pack('>I', zlib.adler32(data))
