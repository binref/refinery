#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Routines to help interpret large binary buffers as arrays of numbers, stored
as consecutive sequences of bytes, all with the same length and byte order.
"""
import array
import sys

from typing import Iterable


_BIG_ENDIAN = sys.byteorder == 'big'
_TYPE_CODES = {
    array.array(t).itemsize: t for t in array.typecodes if t.isupper()
}


def unpack(data: bytes, blocksize: int, bigendian: bool = False) -> Iterable[int]:
    """
    Returns an iterable of integers which have been unpacked from the given `data`
    buffer as chunks of `blocksize` many bytes.
    """
    if blocksize == 1:
        return data
    if blocksize in _TYPE_CODES:
        overlap = len(data) % blocksize
        if overlap != 0:
            data = memoryview(data)[:-overlap]
        unpacked = array.array(_TYPE_CODES[blocksize])
        unpacked.frombytes(data)
        if _BIG_ENDIAN != bigendian:
            unpacked.byteswap()
        return unpacked
    else:
        blocks = zip(*([iter(data)] * blocksize))
        byteorder = ('little', 'big')[bigendian]
        return (int.from_bytes(block, byteorder) for block in blocks)


def pack(data: Iterable[int], blocksize: int, bigendian: bool = False) -> bytearray:
    """
    Returns a bytes object which contains the packed representation of the
    integers in `data`, where each item is encoded using `blocksize` many
    bytes. The numbers are assumed to fit this encoding.
    """
    if blocksize == 1:
        if isinstance(data, bytearray):
            return data
        return bytearray(data)
    if blocksize in _TYPE_CODES:
        if not isinstance(data, array.array):
            tmp = array.array(_TYPE_CODES[blocksize])
            tmp.extend(data)
            data = tmp
        if _BIG_ENDIAN != bigendian:
            data.byteswap()
        return data.tobytes()
    else:
        order = 'big' if bigendian else 'little'
        return B''.join(
            number.to_bytes(blocksize, order) for number in data)
