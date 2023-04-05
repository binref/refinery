#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A rudimentary parser for Dalvik Executable (dex) files. The parser is not yet complete
and currently only parses the string table, which is required for the `refinery.dextr`
unit.

Main Reference: https://source.android.com/devices/tech/dalvik/dex-format
"""
from typing import Generator

import zlib
import hashlib

from refinery.lib.structures import StreamDetour, Struct, StructReader
from refinery.lib.java import JvClassFile


class DexFile(Struct):
    def __init__(self, reader: StructReader, calculate_checks=False):
        if reader.read(4) != b'dex\n':
            raise ValueError('Invalid Signature')
        with StreamDetour(reader, 0x28):
            endian_test_data = reader.u32()
            if endian_test_data == 0x78563412:
                reader.bigendian = True
        self.version = reader.read(4).rstrip(b'\0')

        self.checksum = reader.u32()
        if calculate_checks:
            with StreamDetour(reader):
                self.calculated_checksum = zlib.adler32(reader.read())
        else:
            self.calculated_checksum = None

        self.signature = reader.read(20)
        if calculate_checks:
            with StreamDetour(reader):
                self.calculated_signature = hashlib.sha1(reader.read()).digest()
        else:
            self.calculated_signature = None

        self.size_of_file = reader.u32()
        self.size_of_header = reader.u32()

        if reader.u32() != 0x12345678:
            raise ValueError('Invalid Endian Tag')

        self.link_size = reader.u32()
        self.link_offset = reader.u32()
        self.map_offset = reader.u32()

        self.strings_size = reader.u32()
        self.strings_offset = reader.u32()
        self._reader = reader

    def read_strings(self) -> Generator[str, None, None]:
        size = self.strings_size
        offset = self.strings_offset
        reader = self._reader

        def uleb128():
            value = 0
            more = True
            for k in range(0, 35, 7):
                limb = reader.read_integer(7)
                more = reader.read_bit()
                value |= limb << k
                if not more:
                    break
            assert not more
            return value

        with StreamDetour(reader, offset):
            offsets = [reader.u32() for _ in range(size)]
            for offset in offsets:
                reader.seek(offset)
                size = uleb128()
                if not size:
                    continue
                data = reader.read_c_string()
                string = JvClassFile.decode_utf8m(data)
                yield string
