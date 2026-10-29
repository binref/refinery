"""
Routines to help interpret large binary buffers as arrays of numbers, stored
as consecutive sequences of bytes, all with the same length and byte order.
"""
from __future__ import annotations

import array
import sys

from refinery.lib.types import buf, Iterable

_BIG_ENDIAN = sys.byteorder == 'big'
_TYPE_CODES = {array.array(t).itemsize: t for t in 'BHILQ'}


def unpack(data: buf, blocksize: int, bigendian: bool = False, step: int = 0, pad: bool = False) -> Iterable[int]:
    """
    Returns an iterable of integers which have been unpacked from the given `data`
    buffer as chunks of `blocksize` many bytes. If `pad` is set, an incomplete final
    chunk is padded with zero bytes at its end before it is unpacked.
    """
    data = memoryview(data)
    if not step:
        step = blocksize
    if blocksize == 1:
        if step == blocksize:
            return data
        return data[::step]
    bo = 'big' if bigendian else 'little'
    ub = len(data)
    if not pad:
        ub = ub + 1 - blocksize

    def padded(overlap: int):
        return int.from_bytes(bytes(data[-overlap:]) + bytes(blocksize - overlap), bo)

    if step == blocksize and blocksize in _TYPE_CODES:
        overlap = len(data) % blocksize
        if overlap:
            data = data[:-overlap]
        unpacked = array.array(_TYPE_CODES[blocksize])
        unpacked.frombytes(data)
        if _BIG_ENDIAN != bigendian:
            unpacked.byteswap()
        if pad and overlap:
            unpacked.append(padded(overlap))
        return unpacked
    elif bigendian and pad and (overlap := len(data) % blocksize):
        def chunks():
            for k in range(0, ub - overlap, step):
                yield int.from_bytes(data[k:k + blocksize], bo)
            yield padded(overlap)
        return chunks()
    else:
        return (int.from_bytes(data[k:k + blocksize], bo) for k in range(0, ub, step))


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
