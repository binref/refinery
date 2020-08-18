#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import struct
import re

from Crypto.Util.strxor import strxor

from ... import Unit
from .....lib import chunks
from .....lib.dotnet.header import DotNetHeader, StreamReader, StringPrimitive, UInt32, ParserEOF
from ....compression.lz import lzma


class dncfx(Unit):
    """
    Extracts the encrypted strings from ConfuserX protected .NET execuctables.
    Each decrypted string is returned as a single output.
    """
    _PATTERN_ARRAY_INIT = (
        BR'(\x1F.|\x20....)'      # load size of a chunk
        BR'\x8D.\x00\x00\x01'     # create a UInt32 array
        BR'\x25'                  # dup
        BR'\xD0%s\x04'            # ldtoken: RVA of array data
        BR'\x28.\x00\x00.'        # call to InitializeArray
    )

    def process(self, data):
        header = DotNetHeader(data, parse_resources=False)
        decompressor = lzma()

        class IntegerAssignment:
            def __init__(self, match):
                self.offset = match.start()
                self.value, = struct.unpack('<I', match[1])

        def get_size(match):
            ins = match[1]
            fmt = '<B' if ins[0] == 0x1F else '<I'
            result, = struct.unpack(fmt, ins[-struct.calcsize(fmt):])
            return result

        potential_seeds = [
            IntegerAssignment(m)
            for m in re.finditer(br'\x20(....)', data, re.DOTALL)
        ]

        for entry in header.meta.RVAs:
            offset = header.pe.get_offset_from_rva(entry.RVA)
            index = struct.pack('<I', entry.Field.Index)
            strings_found = 0
            for match in re.finditer(self._PATTERN_ARRAY_INIT % re.escape(index[:3]), data, flags=re.DOTALL):
                ms = match.start()

                def sortkey(t):
                    weight = abs(t.offset - ms)
                    if t.offset < ms:
                        # this weights assignments after the array initialization down, but still
                        # prefers them over assignments that are further away than 2kb
                        weight += 2000
                    return weight

                size = get_size(match)

                if size % 0x10 or size > 10000:
                    continue

                self.log_debug(F'found RVA {entry.Field.Index} initialized with length {size}.')
                potential_seeds.sort(key=sortkey)

                for seed in potential_seeds[1:400]:
                    # the first potential_seed will always be the assignment of the size variable
                    ciphertext = data[offset:offset + size * 4]
                    key = self._xs64star(seed.value)
                    key = chunks.pack(key, 4) + ciphertext[:-0x40]
                    decrypted = strxor(key, ciphertext)
                    try:
                        decompressed = decompressor(decrypted)
                    except Exception as e:
                        self.log_debug(
                            F'decompression failed for seed {seed.value:08X} at offset {seed.offset:08X}: {e}')
                        continue
                    else:
                        self.log_info(
                            F'decompression worked for seed {seed.value:08X} at offset {seed.offset:08X}.')
                    if len(decompressed) < 0x100:
                        continue
                    for string in self._extract_strings(decompressed):
                        strings_found += 1
                        yield string
                    if strings_found > 10:
                        break

    def _xs64star(self, state):
        for i in range(16):
            state ^= (state >> 12) & 0xFFFFFFFF
            state ^= (state << 25) & 0xFFFFFFFF
            state ^= (state >> 27) & 0xFFFFFFFF
            yield state & 0xFFFFFFFF

    def _extract_strings(self, blob):
        reader = StreamReader(blob)
        while reader.tell() < len(blob):
            try:
                size = reader.expect(UInt32)
                string = reader.expect(StringPrimitive, size=size, codec='UTF8', align=4)
            except ParserEOF:
                return
            if string:
                yield string.encode(self.codec)
