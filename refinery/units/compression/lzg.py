#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import Union

import enum
import re

from refinery.units import Unit, RefineryPartialResult
from refinery.lib.structures import MemoryFile, StructReader, Struct


class LZGMethod(enum.IntEnum):
    COPY = 0
    LZG1 = 1


class LZGCheckSum:
    def __init__(self, reader: Union[bytearray, StructReader[bytearray]], size: int = 0):
        if not isinstance(reader, StructReader):
            reader = StructReader(reader)
        self.reader = reader
        self._a = 1
        self._b = 0
        if size:
            self.process(size)

    def __int__(self):
        return ((self._b << 0x10) | self._a)

    def process(self, size: int) -> None:
        a = self._a
        b = self._b
        for c in self.reader.read_exactly(size):
            a = (a + c) & 0xFFFF
            b = (b + a) & 0xFFFF
        self._a = a
        self._b = b


class LZGStream(Struct):
    _LENGTH_DECODE = list(range(2, 30))
    _LENGTH_DECODE.extend((35, 48, 72, 128))

    def __init__(self, reader: StructReader[memoryview]):
        self._body = reader
        magic = reader.peek(3)
        if magic == B'LZG':
            self.has_magic = True
            reader.seekrel(3)
        else:
            self.has_magic = False
        with reader.be:
            dec = reader.u32()
            enc = reader.u32()
            if enc > dec and not self.has_magic:
                enc, dec = dec, enc
            self.encoded_size = enc
            self.decoded_size = dec
            self.checksum = reader.u32()

        if reader.remaining_bytes < self.encoded_size:
            raise EOFError(F'Header announces buffer size of {self.encoded_size}, but only {reader.remaining_bytes} remain in buffer')

        if reader.remaining_bytes == self.encoded_size:
            if self._checks():
                self.method = None
                return
            raise ValueError('Invalid checksum or truncated buffer.')

        method = reader.u8()

        try:
            self.method = LZGMethod(method)
        except ValueError:
            self.method = None
            if self._checks():
                raise ValueError(F'Invalid method code {method}.')
            reader.seekrel(-1)
            self.encoded_size -= 1

        if self.method is LZGMethod.COPY and self.encoded_size != self.decoded_size:
            raise ValueError('Header indicates method COPY but encoded and decoded size are different.')
        if self._checks():
            return

        self._handle_invalid_checksum()

    def _checks(self):
        checker = LZGCheckSum(StructReader(self._body.peek()))
        checker.process(self.encoded_size)
        for tolerance in range(8):
            if int(checker) == self.checksum:
                self.encoded_size += tolerance
                return True
            checker.process(1)
        else:
            return False

    def _find_checksum(self, data: bytearray) -> int:
        a = 1
        b = 0
        t = self.checksum
        for k, c in enumerate(data):
            a = (a + c) & 0xFFFF
            b = (b + a) & 0xFFFF
            s = ((b << 0x10) | a)
            if s == t:
                return k
        return -1

    def _handle_invalid_checksum(self):
        offsets = {}
        for k in range(16):
            offset = self._find_checksum(self._body.peek())
            if offset >= 0:
                offsets[offset] = k + 1
            self._body.seekrel(1)
        if not offsets:
            raise ValueError('Invalid checksum and no working offsets could be found.')
        else:
            closest = min(offsets, key=lambda k: abs(self.encoded_size - k))
            skip = offsets[closest]
            raise ValueError(
                F'Checksum failed; a valid checksum can be obtained by skipping {skip} bytes and then reading {closest}. '
                F'According to the header, the size of the encoded data is {self.encoded_size}.')

    def decompress(self) -> bytearray:
        if self._body is None:
            raise RuntimeError('The decompress method can only be called once.')
        reader = self._body
        self._body = None

        if self.method is LZGMethod.COPY:
            return reader.read(self.encoded_size)

        end = reader.tell() + self.encoded_size
        out = MemoryFile(bytearray())

        markers = reader.read(4)
        pattern = re.compile(B'[%s]' % re.escape(markers), flags=re.DOTALL)
        pos = reader.tell()

        while reader.tell() < end:
            pos = reader.tell()
            hop = pattern.search(reader.getbuffer(), pos)
            if hop is None:
                out.write(reader.read(end - pos))
                break
            hop = hop.start()
            out.write(reader.read(hop - pos))
            code = reader.u8()
            arg1 = reader.u8()
            if not arg1:
                out.write_byte(code)
                continue
            elif code == markers[0]:
                length = self._LENGTH_DECODE[arg1 & 0x1F]
                b2 = reader.u8()
                offset = ((arg1 & 0xE0) << 11) | (b2 << 8) | reader.u8()
                offset += 2056
            elif code == markers[1]:
                length = self._LENGTH_DECODE[arg1 & 0x1F]
                b2 = reader.u8()
                offset = ((arg1 & 0xE0) << 3) | b2
                offset += 8
            elif code == markers[2]:
                length = (arg1 >> 6) + 3
                offset = (arg1 & 0x3F) + 8
            elif code == markers[3]:
                length = self._LENGTH_DECODE[arg1 & 0x1F]
                offset = (arg1 >> 5) + 1
            else:
                raise RuntimeError
            out.replay(offset, length)

        return out.getbuffer()


class lzg(Unit):
    """
    LZG decompression.
    """
    def process(self, data: bytearray):
        stream = LZGStream(data)
        out = stream.decompress()
        if len(out) != stream.decoded_size:
            msg = F'LZG header announced {stream.decoded_size} bytes, but decompressed buffer had size {len(out)}.'
            raise RefineryPartialResult(msg, out)
        return out

    @classmethod
    def handles(cls, data: bytearray):
        if data[:3] == B'LZG':
            return True
