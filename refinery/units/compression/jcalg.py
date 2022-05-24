#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import Optional

from refinery.units import Unit
from refinery.lib.structures import MemoryFile, StructReader


class CompressionSourceData(StructReader[memoryview]):
    """
    A helper class to read bitwise from the compressed input stream.
    """

    def __init__(self, data: bytearray):
        super().__init__(memoryview(data), bigendian=False)
        self._bit_buffer_data: int = 0
        self._bit_buffer_size: int = 0

    def jc_integer(self) -> int:
        value = 1
        while True:
            chunk = self.jc_bits(2)
            value = (value << 1) + (chunk >> 1)
            if not chunk & 1:
                return value

    def jc_bit(self) -> int:
        return self.jc_bits(1)

    def jc_bits(self, count):
        offset = self._bit_buffer_size - count
        bits: int = self._bit_buffer_data
        if offset < 0:
            more = count - self._bit_buffer_size
            assert more <= 32
            self._bit_buffer_data = self.u32()
            self._bit_buffer_size = 32
            bits = (bits << more) | self.jc_bits(more)
        else:
            bits >>= offset
            self._bit_buffer_data ^= bits << offset
            self._bit_buffer_size -= count
        assert self._bit_buffer_data.bit_length() <= self._bit_buffer_size
        assert bits.bit_length() <= count
        return bits


class jcalg(Unit):
    """
    JCALG decompression.
    """
    def __init__(
        self,
        ignore_header: Unit.Arg('-g', help=(
            'Keep decompressing even after the output has reached the final size as given by the header value.')) = False,
    ):
        super().__init__(ignore_header=ignore_header)

    def process(self, data: bytearray):
        with MemoryFile() as output, CompressionSourceData(data) as reader:
            if reader.read(2) != B'JC':
                self.log_warn('data does not begin with magic sequence, assuming that header is missing')
                reader.seek(0)
                size = checksum = None
            else:
                size = reader.u32()
                checksum = reader.u32()
            if self.args.ignore_header:
                size = None
            self._decompress(output, reader, size)
            if size is not None:
                if len(output) > size:
                    self.log_info(F'tuncating to size {size}')
                    output.truncate(size)
                elif len(output) < size:
                    self.log_warn(F'header size was {size}, but only {len(data)} bytes were decompressed')
            data = output.getvalue()
            if checksum:
                c = self._checksum(data)
                if c != checksum:
                    self.log_warn(F'header checksum was {checksum:08X}, computed value is {c:08X}')
            return data

    @classmethod
    def handles(cls, data: bytearray):
        if data.startswith(B'JC'):
            return True

    def _checksum(self, data):
        from refinery.lib import chunks
        checksum = 0
        it = chunks.unpack(data, 4)
        if len(data) % 4:
            import itertools
            it = itertools.chain(it, (int.from_bytes(data[-4:], 'little'),))
        for chunk in it:
            checksum += chunk
            checksum ^= ((chunk & 0x7FFFFFFF) << 1) + (chunk >> 31) + 1
            checksum &= 0xFFFFFFFF
        return checksum

    def _decompress(self, writer: MemoryFile, reader: CompressionSourceData, size: Optional[int] = None):
        index = 1
        base = 8
        literal_bits = None
        literal_offset = None

        def match(delta: int, length: int):
            if delta <= 0:
                raise ValueError
            buffer = writer.getbuffer()
            offset = -delta
            rep, r = divmod(length, delta)
            match = buffer[offset:offset + r]
            if rep > 0:
                match = buffer[offset:] * rep + match
            writer.write(match)

        while True:
            if size and len(writer) >= size:
                break
            if reader.jc_bit():
                b = reader.jc_bits(literal_bits) + literal_offset
                b = b & 0xFF
                writer.write_byte(b)
                continue
            if reader.jc_bit():
                high = reader.jc_integer()
                if(high == 2):
                    match_length = reader.jc_integer()
                else:
                    index = ((high - 3) << base) + reader.jc_bits(base)
                    match_length = reader.jc_integer()
                    if index >= 0x10000:
                        match_length += 3
                    elif index >= 0x37FF:
                        match_length += 2
                    elif index >= 0x27F:
                        match_length += 1
                    elif index <= 127:
                        match_length += 4
                match(index, match_length)
                continue
            if not reader.jc_bit():
                new_index = reader.jc_bits(7)
                match_length = 2 + reader.jc_bits(2)
                if new_index == 0:
                    if match_length == 2:
                        break
                    base = reader.jc_bits(match_length + 1)
                else:
                    index = new_index
                    match(index, match_length)
                continue
            one_byte_phrase_value = reader.jc_bits(4) - 1
            if one_byte_phrase_value == 0:
                writer.write_byte(0)
            elif one_byte_phrase_value > 0:
                b = writer.getbuffer()[-one_byte_phrase_value]
                writer.write_byte(b)
            else:
                if not reader.jc_bit():
                    literal_bits = 7 + reader.jc_bit()
                    literal_offset = 0
                    if literal_bits != 8:
                        literal_offset = reader.jc_bits(8)
                    continue
                while True:
                    for _ in range(0x100):
                        b = reader.jc_bits(8)
                        writer.write_byte(b)
                    if not reader.jc_bit():
                        break
