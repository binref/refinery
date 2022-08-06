#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import Optional

from refinery.units import Unit
from refinery.lib.structures import MemoryFile, StructReader
from refinery.lib.decompression import BitBufferedReader


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
        with MemoryFile() as output, StructReader(data) as reader:
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
        if data[:2] == B'JC':
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

    def _decompress(self, writer: MemoryFile, reader_: StructReader[bytearray], size: Optional[int] = None):
        index = 1
        base = 8
        literal_bits = None
        literal_offset = None
        flags = BitBufferedReader(reader_, 32)

        while True:
            if size and len(writer) >= size:
                break
            if flags.next():
                b = flags.read(literal_bits) + literal_offset
                b = b & 0xFF
                writer.write_byte(b)
                continue
            if flags.next():
                high = flags.variable_length_integer()
                if high == 2:
                    match_length = flags.variable_length_integer()
                else:
                    index = ((high - 3) << base) + flags.read(base)
                    match_length = flags.variable_length_integer()
                    if index >= 0x10000:
                        match_length += 3
                    elif index >= 0x37FF:
                        match_length += 2
                    elif index >= 0x27F:
                        match_length += 1
                    elif index <= 127:
                        match_length += 4
                writer.replay(index, match_length)
                continue
            if not flags.next():
                new_index = flags.read(7)
                match_length = 2 + flags.read(2)
                if new_index == 0:
                    if match_length == 2:
                        break
                    base = flags.read(match_length + 1)
                else:
                    index = new_index
                    writer.replay(index, match_length)
                continue
            one_byte_phrase_value = flags.read(4) - 1
            if one_byte_phrase_value == 0:
                writer.write_byte(0)
            elif one_byte_phrase_value > 0:
                b = writer.getbuffer()[-one_byte_phrase_value]
                writer.write_byte(b)
            else:
                if not flags.next():
                    literal_bits = 7 + flags.next()
                    literal_offset = 0
                    if literal_bits != 8:
                        literal_offset = flags.read(8)
                    continue
                while True:
                    for _ in range(0x100):
                        b = flags.read(8)
                        writer.write_byte(b)
                    if not flags.next():
                        break
