#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from enum import IntEnum, IntFlag
from typing import ByteString, Generator
from zlib import adler32, crc32
from datetime import datetime

from refinery.units import Unit
from refinery.lib.structures import EOF, MemoryFile, StreamDetour, Struct, StructReader


class LZOError(Exception):
    pass


class LZOFlags(IntFlag):
    F_ADLER32_D     = 0x00000001 # noqa
    F_ADLER32_C     = 0x00000002 # noqa
    F_STDIN         = 0x00000004 # noqa
    F_STDOUT        = 0x00000008 # noqa
    F_NAME_DEFAULT  = 0x00000010 # noqa
    F_DOSISH        = 0x00000020 # noqa
    F_H_EXTRA_FIELD = 0x00000040 # noqa
    F_H_GMTDIFF     = 0x00000080 # noqa
    F_CRC32_D       = 0x00000100 # noqa
    F_CRC32_C       = 0x00000200 # noqa
    F_MULTIPART     = 0x00000400 # noqa
    F_H_FILTER      = 0x00000800 # noqa
    F_H_CRC32       = 0x00001000 # noqa
    F_H_PATH        = 0x00002000 # noqa


class LZOMethod(IntEnum):
	M_LZO1X_1    = 1 # noqa
	M_LZO1X_1_15 = 2 # noqa
	M_LZO1X_999  = 3 # noqa


class LZOChunk(Struct):
    def __init__(self, reader: StructReader[memoryview], flags: LZOFlags):
        self.dst_len = reader.u32()
        self.src_len = reader.u32()
        self.checksum_decompressed = reader.u32()

        if flags & LZOFlags.F_ADLER32_C:
            self.dst_a32 = reader.u32()
        if flags & LZOFlags.F_CRC32_C:
            self.dst_c32 = reader.u32()

        if self.src_len < self.dst_len:
            if flags & LZOFlags.F_ADLER32_C:
                self.src_a32 = reader.u32()
            if flags & LZOFlags.F_CRC32_C:
                self.src_c32 = reader.u32()

        self.data = reader.read(self.src_len)


class LZO(Struct):
    def __init__(self, reader: StructReader[memoryview]):
        signature = reader.read(9)

        if signature != B'\x89\x4c\x5a\x4f\x00\x0d\x0a\x1a\x0a':
            raise LZOError(F'Invalid Signature: {signature.hex()}')

        reader.bigendian = True
        self.version = reader.u16()
        if self.version < 0x0900:
            raise LZOError(F'Invalid Version: 0x{self.version:04X}')

        self.lib_version = reader.u16()

        if self.version >= 0x0940:
            self.req_version = reader.u16()
            if self.req_version in range(0x1010, 0x0901):
                raise LZOError(F'Invalid Extract Version: 0x{self.req_version:04X}')
        else:
            self.req_version = None

        method = reader.read_byte()

        if self.version >= 0x0940:
            self.level = reader.read_byte()
            if self.level > 9:
                raise LZOError(F'Invalid level: {self.level}')
        else:
            self.level = None

        try:
            self.method = LZOMethod(method)
        except ValueError:
            raise LZOError(F'Unknown method: {method}')

        if self.level is None:
            if self.method is LZOMethod.M_LZO1X_1_15:
                self.level = 1
            if self.method is LZOMethod.M_LZO1X_1:
                self.level = 3
            if self.method is LZOMethod.M_LZO1X_999:
                self.level = 9

        self.flags = LZOFlags(reader.u32())
        if self.flags & LZOFlags.F_H_FILTER:
            raise LZOError('The header specifies a filter, which is not supported.')

        self.mode = reader.u32()
        self.mtime = reader.u32()

        if self.version >= 0x0940:
            self.gmtdiff = reader.u32()
        else:
            self.gmtdiff = 0

        self.name = reader.read_bytes(reader.read_byte())

        with StreamDetour(reader, 9) as detour:
            algorithm = crc32 if self.flags & LZOFlags.F_H_CRC32 else adler32
            checksum = algorithm(reader.read(detour.cursor - 9))

        self.header_checksum = reader.u32()
        if self.header_checksum != checksum:
            raise LZOError(F'Header checksum is 0x{checksum:X}, header value is 0x{self.checksum:X}.')

        if self.flags & LZOFlags.F_H_EXTRA_FIELD:
            reader.read(reader.u32())
            ec = reader.u32()
            with StreamDetour(reader, 0) as detour:
                algorithm = crc32 if self.flags & LZOFlags.F_H_CRC32 else adler32
                checksum = algorithm(reader.read(detour.whence))
                if ec != checksum:
                    raise LZOError(F'Extra checksum is 0x{checksum:X}, header value is 0x{ec:X}.')

        self.reader = reader

    def __iter__(self) -> Generator[LZOChunk, None, None]:
        while not self.reader.eof:
            try:
                chunk = LZOChunk(self.reader, self.flags)
            except EOF:
                break
            if not chunk.data:
                break
            yield chunk


class lzo(Unit):
    """
    LZO decompression. The code works against simple test cases, but it is known to fail for certain outputs produced by the lzop
    command-line tool when high compression ratio is favoured (i.e. when the -9 switch is used).
    """
    def decompress_stream(self, data: ByteString, LZOv1: bool = False) -> bytearray:
        """
        An implementation of LZO decompression. We use the article
        "[LZO stream format as understood by Linux's LZO decompressor](https://www.kernel.org/doc/html/latest/staging/lzo.html)"
        as a reference since no proper specification is available.
        """
        def integer() -> int:
            length = 0
            while True:
                byte = src.read_byte()
                if byte:
                    return length + byte
                length += 0xFF
                if length > 0x100000:
                    raise LZOError('Too many zeros in integer encoding.')

        def literal(count):
            dst.write(src.read_bytes(count))

        def copy(distance: int, length: int):
            if distance > len(dst):
                raise LZOError(F'Distance {distance} > bufsize {len(dst)}')
            buffer = dst.getbuffer()
            if distance > length:
                start = len(buffer) - distance
                end = start + length
                dst.write(buffer[start:end])
            else:
                block = buffer[-distance:]
                while len(block) < length:
                    block += block[:length - len(block)]
                if len(block) > length:
                    block[length:] = ()
                dst.write(block)

        src = StructReader(memoryview(data))
        dst = MemoryFile()

        state = 0
        first = src.read_byte()

        if first == 0x10:
            raise LZOError('Invalid first stream byte 0x10.')
        elif first <= 0x12:
            src.seekrel(-1)
        elif first <= 0x15:
            state = first - 0x11
            literal(state)
        else:
            state = 4
            literal(first - 0x11)

        while True:
            instruction = src.read_byte()
            if instruction < 0x10:
                if state == 0:
                    length = instruction or integer() + 15
                    state = length + 3
                    if state < 4:
                        raise LZOError('Literal encoding is too short.')
                else:
                    state = instruction & 0b0011
                    D = (instruction & 0b1100) >> 2
                    H = src.read_byte()
                    distance = (H << 2) + D + 1
                    if state >= 4:
                        distance += 0x800
                        length = 3
                    else:
                        length = 2
                    copy(distance, length)
            elif instruction < 0x20:
                L = instruction & 0b0111
                H = instruction & 0b1000
                length = L or integer() + 7
                argument = src.u16()
                state = argument & 3
                distance = (H << 11) + (argument >> 2)
                if not distance:
                    return dst.getbuffer()
                if LZOv1 and distance & 0x803F == 0x803F and length in range(261, 265):
                    raise LZOError('Compressed data contains sequence that is banned in LZOv1.')
                if LZOv1 and distance == 0xBFFF:
                    X = src.read_byte()
                    count = ((X << 3) | L) + 4
                    self.log_debug(F'Writing run of {X} zero bytes according to LZOv1.')
                    dst.write(B'\0' * count)
                else:
                    copy(distance + 0x4000, length + 2)
            elif instruction < 0x40:
                L = instruction & 0b11111
                length = L or integer() + 31
                argument = src.u16()
                state = argument & 3
                distance = (argument >> 2) + 1
                copy(distance, length + 2)
            else:
                if instruction < 0x80:
                    length = 3 + ((instruction >> 5) & 1)
                else:
                    length = 5 + ((instruction >> 5) & 3)
                H = src.read_byte()
                D = (instruction & 0b11100) >> 2
                state = instruction & 3
                distance = (H << 3) + D + 1
                copy(distance, length)
            if state:
                literal(state)

    def process(self, data):
        try:
            lzo = LZO(data)
        except LZOError:
            self.log_info('Not an LZO archive, processing raw stream.')
            return self.decompress_stream(data)
        with MemoryFile() as output:
            for k, chunk in enumerate(lzo, 1):
                self.log_debug(F'decompressing chunk {k}')
                output.write(self.decompress_stream(chunk.data))
            return self.labelled(
                output.getbuffer(),
                path=lzo.name,
                date=datetime.utcfromtimestamp(lzo.mtime)
            )
