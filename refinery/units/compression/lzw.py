#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from enum import IntEnum
from typing import Optional
from array import array

import itertools

from refinery.units import Unit, RefineryPartialResult
from refinery.lib.structures import MemoryFile, StructReader


class LZW(IntEnum):
    BITS = 0x10
    BLKMODE = 0x80
    RESERVED = 0x60
    MAXBITS = 0x1F
    INIT_BITS = 9
    CLEAR = 0x100
    FIRST = 0x101
    INBUF_ALLOC = 0x8000
    INBUF_EXTRA = 64
    OUTBUF_ALLOC = 16384
    OUTBUF_EXTRA = 2048
    DIST_BUFSIZE = 0x8000
    WSIZE = 0x8000


class lzw(Unit):
    '''
    LZW decompression based on ancient Unix sources.
    '''

    _MAGIC = B'\x1F\x9D'

    def process(self, compressed: bytearray):
        out = MemoryFile()
        inf = StructReader(compressed)

        if inf.peek(2) != self._MAGIC:
            self.log_info('No LZW signature found, assuming raw stream.')
            maxbits = LZW.BITS
            block_mode = True
        else:
            inf.seekrel(2)
            maxbits = inf.read_integer(5)
            if inf.read_integer(2) != 0:
                self.log_info('reserved bits were set in LZW header')
            block_mode = bool(inf.read_bit())

        if maxbits > LZW.BITS:
            raise ValueError(F'Compressed with {maxbits} bits; cannot handle file.')

        maxmaxcode = 1 << maxbits

        ibuf = bytearray(LZW.INBUF_ALLOC + LZW.INBUF_EXTRA)
        obuf = bytearray(LZW.OUTBUF_ALLOC + LZW.OUTBUF_EXTRA)
        ibytes = 0
        obytes = 0
        stack = bytearray(LZW.DIST_BUFSIZE)
        tab_suffix = bytearray(LZW.WSIZE * 2)
        tab_prefix = array('H', itertools.repeat(0, 1 << LZW.BITS))

        n_bits = LZW.INIT_BITS
        maxcode = (1 << n_bits) - 1
        bitmask = (1 << n_bits) - 1
        oldcode = ~0
        finchar = +0
        posbits = 0
        rsize = 0
        outpos = 0
        insize = 0

        free_entry = LZW.FIRST if block_mode else 0x100
        tab_suffix[:0x100] = range(0x100)
        resetbuf = True

        while rsize > 0 or resetbuf:
            resetbuf = False

            o = posbits >> 3
            e = insize - o
            for i in range(e):
                ibuf[i] = ibuf[i + o]
            insize = e
            posbits = 0

            if insize < LZW.INBUF_EXTRA:
                _buf = inf.read(LZW.INBUF_ALLOC)
                rsize = len(_buf)
                ibuf[insize:insize + rsize] = _buf
                insize += rsize
                ibytes += rsize

            if rsize == 0:
                inbits = (insize - insize % n_bits) << 3
            else:
                inbits = (insize << 3) - (n_bits - 1)

            while inbits > posbits:
                if free_entry > maxcode:
                    posbits = ((posbits - 1) + ((n_bits << 3) - (posbits - 1 + (n_bits << 3)) % (n_bits << 3)))
                    n_bits += 1
                    if (n_bits == maxbits):
                        maxcode = maxmaxcode
                    else:
                        maxcode = (1 << n_bits) - 1
                    bitmask = (1 << n_bits) - 1
                    resetbuf = True
                    break

                # input(inbuf,posbits,code,n_bits,bitmask);
                p = memoryview(ibuf)[posbits >> 3:]
                code = ((p[0] | p[1] << 8 | p[2] << 16) >> (posbits & 7)) & bitmask
                posbits += n_bits

                if oldcode == -1:
                    if code >= 256:
                        raise ValueError('corrupt input.')
                    oldcode = code
                    finchar = oldcode
                    obuf[outpos] = finchar
                    outpos += 1
                    continue

                if code == LZW.CLEAR and block_mode:
                    tab_prefix[:0x100] = array('H', itertools.repeat(0, 0x100))
                    free_entry = LZW.FIRST - 1
                    posbits = ((posbits - 1) + ((n_bits << 3) - (posbits - 1 + (n_bits << 3)) % (n_bits << 3)))
                    n_bits = LZW.INIT_BITS
                    maxcode = (1 << n_bits) - 1
                    bitmask = (1 << n_bits) - 1
                    resetbuf = True
                    break

                incode = code
                stackp = LZW.DIST_BUFSIZE

                if code >= free_entry:
                    if code > free_entry:
                        if outpos > 0:
                            out.write(memoryview(obuf)[:outpos])
                            obytes += outpos
                        raise RefineryPartialResult('corrupt input.', out.getbuffer())
                    stackp -= 1
                    stack[stackp] = finchar
                    code = oldcode

                while code >= 256:
                    stackp -= 1
                    stack[stackp] = tab_suffix[code]
                    code = tab_prefix[code]

                finchar = tab_suffix[code]
                stackp -= 1
                stack[stackp] = finchar
                i = LZW.DIST_BUFSIZE - stackp

                if outpos + i >= LZW.OUTBUF_ALLOC:
                    while True:
                        if (i > LZW.OUTBUF_ALLOC - outpos):
                            i = LZW.OUTBUF_ALLOC - outpos
                        if i > 0:
                            obuf[outpos:outpos + i] = stack[stackp:stackp + i]
                            outpos += i
                        if outpos >= LZW.OUTBUF_ALLOC:
                            out.write(memoryview(obuf)[:outpos])
                            obytes += outpos
                            outpos = 0
                        stackp += i
                        i = LZW.DIST_BUFSIZE - stackp
                        if i <= 0:
                            break
                else:
                    obuf[outpos:outpos + i] = stack[stackp:stackp + i]
                    outpos += i

                code = free_entry

                if code < maxmaxcode:
                    tab_prefix[code] = oldcode & 0xFFFF
                    tab_suffix[code] = finchar & 0x00FF
                    free_entry = code + 1

                oldcode = incode

        if outpos > 0:
            out.write(memoryview(obuf)[:outpos])
            obytes += outpos

        return out.getvalue()

    @classmethod
    def handles(self, data: bytearray) -> Optional[bool]:
        sig = self._MAGIC
        if data[:len(sig)] == sig:
            return True
