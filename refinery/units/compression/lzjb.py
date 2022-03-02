#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib.structures import StructReader
from refinery.units import Unit

_MATCH_LEN = 6
_MATCH_MIN = 3
_MATCH_MAX = (1 << _MATCH_LEN) + (_MATCH_MIN - 1)

_OFFSET_MASK = (1 << (16 - _MATCH_LEN)) - 1
_LEMPEL_SIZE = 0x1000


class lzjb(Unit):
    """
    LZJB compression and decompression. This LZ-type compression is used in the ZFS file system.
    """
    def reverse(self, src):
        # https://web.archive.org/web/20100807223517/ ..
        # .. http://cvs.opensolaris.org/source/xref/onnv/onnv-gate/usr/src/uts/common/fs/zfs/lzjb.c
        output = bytearray()
        lempel = [0] * _LEMPEL_SIZE
        copymask = 0x80
        position = 0
        while position < len(src):
            copymask <<= 1
            if copymask >= 0x100:
                copymask = 1
                copymap = len(output)
                output.append(0)
            if position > len(src) - _MATCH_MAX:
                output.append(src[position])
                position += 1
                continue
            hsh = (src[position] << 16) + (src[position + 1] << 8) + src[position + 2]
            hsh += hsh >> 9
            hsh += hsh >> 5
            hsh %= len(lempel)
            offset = (position - lempel[hsh]) & _OFFSET_MASK
            lempel[hsh] = position
            cpy = position - offset
            if cpy >= 0 and cpy != position and src[position:position + 3] == src[cpy:cpy + 3]:
                output[copymap] |= copymask
                for mlen in range(_MATCH_MIN, min(len(src) - position, _MATCH_MAX)):
                    if src[position + mlen] != src[cpy + mlen]:
                        break
                output.append(((mlen - _MATCH_MIN) << (8 - _MATCH_LEN)) | (offset >> 8))
                output.append(offset & 255)
                position += mlen
            else:
                output.append(src[position])
                position += 1
        return output

    def process(self, data):
        dst = bytearray()
        src = StructReader(data)
        while not src.eof:
            copy = src.read_byte()
            for mask in (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80):
                if src.eof:
                    break
                if not copy & mask:
                    dst.append(src.read_byte())
                    continue
                elif not dst:
                    raise ValueError('copy requested against empty buffer')
                with src.be:
                    match_len = src.read_integer(6) + _MATCH_MIN
                    match_pos = src.read_integer(10)
                if not match_pos or match_pos > len(dst):
                    raise RuntimeError(F'invalid match offset at position {src.tell()}')
                match_pos = len(dst) - match_pos
                while match_len > 0:
                    match = dst[match_pos:match_pos + match_len]
                    dst.extend(match)
                    match_pos += len(match)
                    match_len -= len(match)
        return dst
