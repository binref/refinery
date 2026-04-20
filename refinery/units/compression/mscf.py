from __future__ import annotations

import enum
import zlib

from typing import Callable

from refinery.lib.structures import MemoryFile, StructReader
from refinery.lib.types import Param
from refinery.units import Arg, Unit

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
    Decompress data using the Microsoft Compression Format (MSZIP, XPRESS, LZMS).
    """

    _SIGNATURE = B'\x0A\x51\xE5\xC0'

    def __init__(
        self,
        mode: Param[str | None, Arg.Option(choices=MODE, help=(
            'Manually select decompression mode ({choices}); by default the unit attempts to derive the '
            'mode from the header, but this will fail for raw streams. However, even if a header is '
            'found, a manually specified mode will take precedence.'))] = None,
    ):
        super().__init__(mode=Arg.AsOption(mode, MODE))

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
                    return writer.getvalue()

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
            return writer.getvalue()

    def _get_handler(self, mode: MODE) -> Callable[[StructReader, MemoryFile, int | None], None]:
        decompress = {
            mode.MSZIP       : self._decompress_mszip,
            mode.XPRESS_HUFF : self._decompress_xpress_huffman,
            mode.XPRESS      : self._decompress_xpress,
            mode.LZMS        : self._decompress_lzms,
        }.get(mode, None)
        if decompress is None:
            raise NotImplementedError(F'algorithm {mode.name} is not yet implemented')
        return decompress

    def _decompress_lzms(self, reader: StructReader, writer: MemoryFile, target: int | None = None) -> None:
        src_data = reader.read()
        if len(src_data) < 4 or (len(src_data) & 1):
            raise ValueError('Invalid Input for LZMS.')
        if target is None:
            target = len(src_data) * 16
        from refinery.lib.lzms import lzms_decompress
        writer.write(lzms_decompress(src_data, target))

    def _decompress_mszip(self, reader: StructReader, writer: MemoryFile, target: int | None = None):
        header = bytes(reader.read(2))
        if header != B'CK':
            raise ValueError(F'chunk did not begin with CK header, got {header!r} instead')
        decompress = zlib.decompressobj(-zlib.MAX_WBITS, zdict=writer.getvalue())
        writer.write(decompress.decompress(reader.read()))
        writer.write(decompress.flush())

    def _decompress_xpress_huffman(
        self,
        reader: StructReader,
        writer: MemoryFile,
        target: int | None = None,
        max_chunk_size: int = 0x10000
    ) -> None:
        from refinery.lib.fast.xpress import xpress_huffman_decompress
        raw = bytes(reader.read())
        actual_target = target if target is not None else 0
        result = xpress_huffman_decompress(raw, actual_target, max_chunk_size)
        writer.write(result)

    def _decompress_xpress(self, reader: StructReader, writer: MemoryFile, target: int | None = None) -> None:
        from refinery.lib.fast.xpress import xpress_decompress
        raw = bytes(reader.read())
        actual_target = target if target is not None else 0
        result = xpress_decompress(raw, actual_target)
        writer.write(result)

    @classmethod
    def handles(cls, data) -> bool | None:
        if data[:len(cls._SIGNATURE)] == cls._SIGNATURE:
            return True
