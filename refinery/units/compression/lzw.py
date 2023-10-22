#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from enum import IntEnum
from typing import Optional
from array import array

import itertools

from refinery.units import Unit, RefineryPartialResult
from refinery.lib.structures import MemoryFile, StructReader


class LZW(IntEnum):
    INIT_BITS = 9
    BITS = 0x10
    CLEAR = 0x100
    FIRST = 0x101
    WSIZE = 0x8000
    EXTRA = 0x40


class lzw(Unit):
    '''
    LZW decompression based on ancient Unix sources.
    '''

    _MAGIC = B'\x1F\x9D'

    def process(self, data: bytearray):
        out = MemoryFile()
        inf = StructReader(memoryview(data))

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

        ibuf = inf.read()

        tab_suffix = bytearray(LZW.WSIZE * 2)
        tab_prefix = array('H', itertools.repeat(0, 1 << LZW.BITS))

        n_bits = LZW.INIT_BITS
        maxcode = (1 << n_bits) - 1
        bitmask = (1 << n_bits) - 1
        oldcode = ~0
        finchar = +0
        posbits = +0

        free_entry = LZW.FIRST if block_mode else 0x100
        tab_suffix[:0x100] = range(0x100)
        resetbuf = True

        while resetbuf:
            resetbuf = False

            ibuf = ibuf[posbits >> 3:]
            insize = len(ibuf)
            posbits = 0

            if insize < LZW.EXTRA:
                inbits = (insize - insize % n_bits) << 3
            else:
                inbits = (insize << 3) - (n_bits - 1)

            while inbits > posbits:
                if free_entry > maxcode:
                    n = n_bits << 3
                    p = posbits - 1
                    posbits = p + (n - (p + n) % n)
                    n_bits += 1
                    if (n_bits == maxbits):
                        maxcode = maxmaxcode
                    else:
                        maxcode = (1 << n_bits) - 1
                    bitmask = (1 << n_bits) - 1
                    resetbuf = True
                    break

                p = ibuf[posbits >> 3:]
                code = int.from_bytes(p[:3], 'little') >> (posbits & 7) & bitmask
                posbits += n_bits

                if oldcode == -1:
                    if code >= 256:
                        raise ValueError('corrupt input.')
                    oldcode = code
                    finchar = oldcode
                    out.write_byte(finchar)
                    continue

                if code == LZW.CLEAR and block_mode:
                    tab_prefix[:0x100] = array('H', itertools.repeat(0, 0x100))
                    free_entry = LZW.FIRST - 1
                    n = n_bits << 3
                    p = posbits - 1
                    posbits = p + (n - (p + n) % n)
                    n_bits = LZW.INIT_BITS
                    maxcode = (1 << n_bits) - 1
                    bitmask = (1 << n_bits) - 1
                    resetbuf = True
                    break

                incode = code
                stack = bytearray()

                if code >= free_entry:
                    if code > free_entry:
                        raise RefineryPartialResult('corrupt input.', out.getbuffer())
                    stack.append(finchar)
                    code = oldcode
                while code >= 256:
                    stack.append(tab_suffix[code])
                    code = tab_prefix[code]

                finchar = tab_suffix[code]
                stack.append(finchar)
                stack.reverse()
                out.write(stack)
                code = free_entry

                if code < maxmaxcode:
                    tab_prefix[code] = oldcode & 0xFFFF
                    tab_suffix[code] = finchar & 0x00FF
                    free_entry = code + 1

                oldcode = incode

        return out.getvalue()

    @classmethod
    def handles(self, data: bytearray) -> Optional[bool]:
        sig = self._MAGIC
        if data[:len(sig)] == sig:
            return True
