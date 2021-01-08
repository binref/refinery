#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Routines to help interpret large binary buffers as arrays of numbers, stored
as consecutive sequences of bytes, all with the same length and byte order.
"""
from typing import Iterable


def unpack(data: bytes, blocksize: int, bigendian: bool = False):
    """
    Returns an iterable of integers which have been unpacked from the given `data`
    buffer as chunks of `blocksize` many bytes.
    """
    if blocksize == 1:
        return data
    if blocksize in (2, 4, 8):
        try:
            import numpy
        except ModuleNotFoundError:
            numpy = None
        order = '<>'[bigendian]
        count = len(data) // blocksize
        if numpy:
            dtype = numpy.dtype(F'{order}u{blocksize}')
            return (int(x) for x in numpy.frombuffer(data, dtype, count))
        else:
            import struct
            scode = {2: 'H', 4: 'L', 8: 'Q'}[blocksize]
            return struct.unpack(F'{order}{count}{scode}', data[:count * blocksize])
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
        return bytearray(data)
    if blocksize in (2, 4, 8):
        try:
            import numpy
        except ModuleNotFoundError:
            numpy = None
        order = '<>'[bigendian]
        if numpy:
            dtype = numpy.dtype(F'{order}u{blocksize}')
            return numpy.fromiter(data, dtype).tobytes()
        else:
            import struct
            scode = {2: 'H', 4: 'L', 8: 'Q'}[blocksize]
            return struct.pack(F'{order}{len(data)}{scode}', *data)
    byteorder = ('little', 'big')[bigendian]
    return B''.join(number.to_bytes(blocksize, byteorder) for number in data)
