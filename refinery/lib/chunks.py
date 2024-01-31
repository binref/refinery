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
_TYPE_CODES = {array.array(t).itemsize: t for t in 'BHILQ'}


def unpack(data: bytes, blocksize: int, bigendian: bool = False, step: int = 0, pad: bool = False) -> Iterable[int]:
    """
    Returns an iterable of integers which have been unpacked from the given `data`
    buffer as chunks of `blocksize` many bytes.
    """
    view = memoryview(data)
    if not step:
        step = blocksize
    if blocksize == 1:
        if step == blocksize:
            return data
        return view[::step]
    bo = 'big' if bigendian else 'little'
    ub = len(view)
    if not pad:
        ub = ub + 1 - blocksize
    if step == blocksize and blocksize in _TYPE_CODES:
        overlap = len(data) % blocksize
        if overlap:
            data = view[:-overlap]
        unpacked = array.array(_TYPE_CODES[blocksize])
        unpacked.frombytes(data)
        if _BIG_ENDIAN != bigendian:
            unpacked.byteswap()
        if pad and overlap:
            unpacked.append(int.from_bytes(view[-overlap:], bo))
        return unpacked
    else:
        return (int.from_bytes(view[k:k + blocksize], bo) for k in range(0, ub, step))


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
    out = bytearray()
    if blocksize in _TYPE_CODES:
        if not isinstance(data, array.array):
            tmp = array.array(_TYPE_CODES[blocksize])
            tmp.extend(data)
            data = tmp
        if _BIG_ENDIAN != bigendian:
            data.byteswap()
        out[:] = memoryview(data)
    else:
        order = 'big' if bigendian else 'little'
        for number in data:
            out.extend(number.to_bytes(blocksize, order))
    return out
