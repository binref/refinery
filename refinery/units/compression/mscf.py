#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Callable, Optional

import zlib
import enum

from refinery.lib.structures import StructReader, MemoryFile
from refinery.lib.decompression import make_huffman_decode_table, read_huffman_symbol, BitBufferedReader
from refinery.units import Unit


XPRESS_NUM_CHARS        = 256    # noqa
XPRESS_NUM_SYMBOLS      = 512    # noqa   
XPRESS_MAX_CODEWORD_LEN = 15     # noqa
XPRESS_MIN_OFFSET       = 1      # noqa
XPRESS_MAX_OFFSET       = 65535  # noqa
XPRESS_MIN_MATCH_LEN    = 3      # noqa
XPRESS_MAX_MATCH_LEN    = 65538  # noqa
XPRESS_TABLEBITS        = 11     # noqa

COMPRESS_MAX_CHUNK = 0x4000000


class MODE(enum.IntEnum):
    MSZIP       = 2  # noqa
    XPRESS      = 3  # noqa
    XPRESS_HUFF = 4  # noqa
    LZMS        = 5  # noqa


class mscf(Unit):
    """
    The Microsoft Compression Format unit implements the format and algorithms used by the Microsoft
    Compression API. The implementation for LZMS is currently missing, but MSZIP and XPRESS (both
    with and without Huffman table) are supported. This pure Python implementation is very slow when
    compared to native code, so decompressing very large inputs can take several minutes.
    """

    _SIGNATURE = B'\x0A\x51\xE5\xC0'

    def __init__(
        self,
        mode: Unit.Arg.Option(choices=MODE, help=(
            'Manually select decompression mode ({choices}); by default the unit attempts to derive the '
            'mode from the header, but this will fail for raw streams. However, even if a header is '
            'found, a manually specified mode will take precedence.')) = None,
    ):
        mode = Unit.Arg.AsOption(mode, MODE)
        super().__init__(mode=mode)

    def process(self, data):
        mode: MODE = self.args.mode
        with StructReader(memoryview(data)) as reader, MemoryFile() as writer:
            reader: StructReader[memoryview]
            check = zlib.crc32(reader.peek(6))
            magic = reader.read(4)
            if magic != self._SIGNATURE:
                if mode is None:
                    self.log_warn(
                        F'data starts with {magic.hex().upper()} rather than the expected sequence '
                        F'{self._SIGNATURE.hex().upper()}; this could be a raw stream.')
                else:
                    reader.seek(0)
                    handler = self._get_handler(mode)
                    handler(reader, writer, None)
                    return writer.getbuffer()

            header_size = reader.u16()
            if header_size != 24:
                self.log_warn(F'the header size {header_size} was not equal to 24')

            crc32byte = reader.u8()
            check = zlib.crc32(reader.peek(0x11), check) & 0xFF
            if check != crc32byte:
                self.log_warn(F'the CRC32 check byte was {crc32byte}, computed value was {check}')

            _mode_code = reader.u8()

            try:
                _mode = MODE(_mode_code)
            except ValueError:
                msg = F'header contains unknown compression type code {_mode_code}'
                if mode is None:
                    raise ValueError(msg)
                else:
                    self.log_warn(msg)
            else:
                if mode is not None and mode != _mode:
                    logger = self.log_warn
                else:
                    logger = self.log_info
                    mode = _mode
                logger(F'header specifies algorithm {_mode.name}')

            self.log_info(F'using algorithm {mode.name}')
            decompress = self._get_handler(mode)

            final_size = reader.u32()
            _unknown_1 = reader.u32()
            chunk_size = reader.u32()
            _unknown_2 = reader.u32()

            if _unknown_1 != 0:
                self.log_warn(F'unknown value 1 was unexpectedly nonzero: 0x{_unknown_1:08X}')
            if _unknown_2 != 0:
                self.log_warn(F'unknown value 2 was unexpectedly nonzero: 0x{_unknown_2:08X}')

            self.log_debug(F'final size: 0x{final_size:08X}')
            self.log_debug(F'chunk size: 0x{chunk_size:08X}')

            if chunk_size > COMPRESS_MAX_CHUNK:
                raise ValueError('the header chunk size is greater than the maximum value')

            while len(writer) < final_size:
                src_size = reader.u32()
                src_data = reader.read(src_size)
                if len(src_data) != src_size:
                    raise IndexError(F'Attempted to read {src_size} bytes, but got only {len(src_data)}.')
                if src_size + len(writer) == final_size:
                    self.log_debug(F'final chunk is uncompressed, appending {src_size} raw bytes to output')
                    writer.write(src_data)
                    break
                self.log_debug(F'reading chunk of size {src_size}')
                start = writer.tell()
                chunk = StructReader(src_data)
                target = min(chunk_size, final_size - len(writer))
                decompress(chunk, writer, target)
                writer.flush()
                written = writer.tell() - start
                if written != target:
                    raise RuntimeError(F'decompressed output had unexpected size {written} instead of {chunk_size}')

            if not reader.eof:
                self.log_info(F'compression complete with {reader.remaining_bytes} bytes remaining in input')
            return writer.getbuffer()

    def _get_handler(self, mode: MODE) -> Callable[[StructReader, MemoryFile, Optional[int]], None]:
        decompress = {
            mode.MSZIP       : self._decompress_mszip,
            mode.XPRESS_HUFF : self._decompress_xpress_huffman,
            mode.XPRESS      : self._decompress_xpress,
        }.get(mode, None)
        if decompress is None:
            raise NotImplementedError(F'algorithm {mode.name} is not yet implemented')
        return decompress

    def _decompress_mszip(self, reader: StructReader, writer: MemoryFile, target: Optional[int] = None):
        header = bytes(reader.read(2))
        if header != B'CK':
            raise ValueError(F'chunk did not begin with CK header, got {header!r} instead')
        decompress = zlib.decompressobj(-zlib.MAX_WBITS, zdict=writer.getbuffer())
        writer.write(decompress.decompress(reader.read()))
        writer.write(decompress.flush())

    def _decompress_xpress_huffman(
        self,
        reader: StructReader,
        writer: MemoryFile,
        target: Optional[int] = None,
        max_chunk_size: int = 0x10000
    ) -> None:
        limit = writer.tell()
        if target is not None:
            target += limit

        while not reader.eof:

            if reader.remaining_bytes < XPRESS_NUM_SYMBOLS // 2:
                raise IndexError(
                    F'There are only {reader.remaining_bytes} bytes reamining in the input buffer,'
                    F' but at least {XPRESS_NUM_SYMBOLS // 2} are required to read a Huffman table.')

            table = bytearray(reader.read_integer(4) for _ in range(XPRESS_NUM_SYMBOLS))
            table = make_huffman_decode_table(table, XPRESS_TABLEBITS, XPRESS_MAX_CODEWORD_LEN)
            limit = limit + max_chunk_size
            flags = BitBufferedReader(reader, 16)

            while True:
                position = writer.tell()
                if position == target:
                    if reader.remaining_bytes:
                        self.log_info(F'chunk decompressed with {reader.remaining_bytes} bytes remaining in input buffer')
                    return
                if position >= limit:
                    if position > limit:
                        limit = position
                        self.log_info(F'decompression of one chunk generated more than the limit of {max_chunk_size} bytes')
                    flags.collect()
                    break
                try:
                    sym = read_huffman_symbol(flags, table, XPRESS_TABLEBITS, XPRESS_MAX_CODEWORD_LEN)
                except EOFError:
                    self.log_debug('end of file while reading huffman symbol')
                    break
                if sym < XPRESS_NUM_CHARS:
                    writer.write_byte(sym)
                    continue
                length = sym & 0xF
                offsetlog = (sym >> 4) & 0xF
                flags.collect()
                if reader.eof:
                    break
                offset = (1 << offsetlog) | flags.read(offsetlog)
                if length == 0xF:
                    nudge = reader.read_byte()
                    if nudge < 0xFF:
                        length += nudge
                    else:
                        length = reader.u16() or reader.u32()
                length += XPRESS_MIN_MATCH_LEN
                writer.replay(offset, length)

    def _decompress_xpress(self, reader: StructReader, writer: MemoryFile, target: Optional[int] = None) -> bytearray:
        if target is not None:
            target += writer.tell()
        flags = BitBufferedReader(reader)
        nibble_cache = None
        while not reader.eof:
            if target is not None and writer.tell() >= target:
                return
            if not flags.next():
                writer.write(reader.read(1))
                continue
            offset, length = divmod(reader.u16(), 8)
            offset += 1
            if length == 7:
                length = nibble_cache
                if length is None:
                    length_pair = reader.u8()
                    nibble_cache = length_pair >> 4
                    length = length_pair & 0xF
                else:
                    nibble_cache = None
                if length == 15:
                    length = reader.u8()
                    if length == 0xFF:
                        length = reader.u16() or reader.u32()
                        length -= 22
                        if length < 0:
                            raise RuntimeError(F'Invalid match length of {length} for long delta sequence')
                    length += 15
                length += 7
            length += 3
            writer.replay(offset, length)

    @classmethod
    def handles(cls, data: bytearray) -> Optional[bool]:
        sig = cls._SIGNATURE
        if data[:len(sig)] == sig:
            return True
