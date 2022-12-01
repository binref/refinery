#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units import Unit, Arg, RefineryPartialResult
from refinery.lib.structures import MemoryFile, Struct, StructReader

import itertools

_MAX_LIT = 1 << 5
_MAX_OFF = 1 << 13
_MAX_REF = ((1 << 8) + (1 << 3))

_HSLOG = 16
_HSIZE = 1 << _HSLOG


class LZFHeader(Struct):
    MAGIC = B'ZV'

    def __init__(self, reader: StructReader):
        if reader.read(2) != self.MAGIC:
            raise ValueError('Invalid header magic.')
        tmp = reader.read_byte()
        if tmp and tmp != 1:
            raise ValueError(F'Invalid type code: {tmp}')
        self.compressed = bool(tmp)
        with reader.be:
            tmp = reader.u16()
            if self.compressed:
                self.encoded_size = tmp
                self.decoded_size = reader.u16()
            else:
                self.encoded_size = tmp
                self.decoded_size = tmp


class lzf(Unit):
    """
    This unit implements LZF compression and decompression.
    """

    def __init__(self, fast: Arg.Switch('-x', help='Enable fast compression mode.') = False):
        super().__init__(fast=fast)

    def reverse(self, data):
        def FRST(p: memoryview) -> int:
            return ((p[0]) << 8) | p[1]

        def NEXT(v: int, p: memoryview) -> int:
            return ((v << 8) | p[2]) & 0xFFFFFFFF

        def DELTA(p: memoryview):
            return view.nbytes - p.nbytes

        if self.args.fast:
            def HIDX(h: int) -> int:
                return (((h >> (3 * 8 - _HSLOG)) - h * 5) & (_HSIZE - 1))
        else:
            def HIDX(h: int) -> int:
                q = (h ^ (h << 5))
                return (((q >> (3 * 8 - _HSLOG)) - h * 5) & (_HSIZE - 1))

        if not data:
            return data

        ip = view = memoryview(data)
        op = bytearray()

        if len(data) == 1:
            op.append(0)
            op.extend(data)
            return op

        hval = FRST(ip)
        htab = [0] * _HSIZE
        fast = 1 if self.args.fast else 0

        lit = 0

        def begin_literal():
            nonlocal lit
            op.append(0)
            lit = 0

        def advance_literal():
            nonlocal lit, ip
            lit += 1
            op.append(ip[0])
            ip = ip[1:]
            if lit == _MAX_LIT:
                op[-lit - 1] = lit - 1
                begin_literal()

        def commit_literal():
            if lit > 0:
                op[-lit - 1] = lit - 1
            else:
                op.pop()

        begin_literal()

        while ip.nbytes > 2:
            hval = NEXT(hval, ip)
            hpos = HIDX(hval)
            ipos = DELTA(ip)
            length = 2
            r, htab[hpos] = htab[hpos], ipos
            off = ipos - r - 1
            ref = view[r:]

            if off >= _MAX_OFF or r <= 0 or ref[:3] != ip[:3]:
                advance_literal()
                continue
            else:
                commit_literal()

            maxlen = min(_MAX_REF, ip.nbytes - length)

            while True:
                length += 1
                if length >= maxlen or ref[length] != ip[length]:
                    length -= 2
                    break

            if length < 7:
                op.append((off >> 8) + (length << 5))
            else:
                op.append((off >> 8) + (7 << 5))
                op.append(length - 7)

            op.append(off & 0xFF)
            begin_literal()

            if ip.nbytes <= length + 3:
                ip = ip[length + 2:]
                break
            if fast:
                ip = ip[length:]
                hval = FRST(ip)
                for _ in range(2):
                    hval = NEXT(hval, ip)
                    htab[HIDX(hval)] = DELTA(ip)
                    ip = ip[1:]
            else:
                ip = ip[1:]
                for _ in range(length + 1):
                    hval = NEXT(hval, ip)
                    htab[HIDX(hval)] = DELTA(ip)
                    ip = ip[1:]
        while ip.nbytes:
            advance_literal()
        commit_literal()
        return op

    def _decompress_chunk(self, data: memoryview, out: MemoryFile):
        ip = StructReader(data)
        while not ip.eof:
            ctrl = ip.u8()
            if ctrl < 0B100000:
                ctrl += 1
                out.write(ip.read_exactly(ctrl))
            else:
                length = ctrl >> 5
                offset = 1 + ((ctrl & 0B11111) << 8)
                if length == 7:
                    length += ip.u8()
                offset += ip.u8()
                length += 2
                out.replay(offset, length)

    def process(self, data):
        mem = memoryview(data)
        out = MemoryFile()

        try:
            reader = StructReader(mem)
            header = LZFHeader(reader)
        except Exception:
            self.log_info('no header detected, decompressing as raw stream')
            self._decompress_chunk(mem, out)
            return out.getvalue()

        for k in itertools.count(1):
            self.log_info(F'chunk: e=0x{header.encoded_size:04X} d=0x{header.decoded_size:04X}')
            chunk = reader.read(header.encoded_size)
            if header.compressed:
                self._decompress_chunk(chunk, out)
            else:
                out.write(chunk)
            if reader.eof:
                break
            try:
                header = LZFHeader(reader)
            except Exception as E:
                msg = F'failed parsing next header after {k} chunks: {E!s}'
                raise RefineryPartialResult(msg, out.getvalue())

        return out.getvalue()
