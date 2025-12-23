from __future__ import annotations

from enum import IntFlag
from itertools import product, repeat
from lzma import (
    FILTER_DELTA,
    FILTER_LZMA1,
    FILTER_LZMA2,
    FORMAT_ALONE,
    FORMAT_RAW,
    FORMAT_XZ,
    PRESET_EXTREME,
    LZMACompressor,
    LZMADecompressor,
    LZMAError,
)

from refinery.lib.decompression import parse_lzma_properties
from refinery.lib.id import buffer_contains
from refinery.lib.structures import MemoryFile
from refinery.lib.types import Param, buf
from refinery.units import Arg, RefineryPartialResult, Unit

__all__ = ['lzma', '_auto_decompress_lzma']


class F(IntFlag):
    DEFAULT = 0
    INJECT = 1
    STEPWISE = 2


class lzma(Unit):
    """
    LZMA compression and decompression.
    """

    _SEARCH_MIN_DICT = 0x1_0000
    _SEARCH_MAX_DICT = 0x1000_0000
    _SEARCH_MAX_BLOW = 1.2
    _SEARCH_SKIP1 = range(9)
    _SEARCH_SKIP2 = (0, 8, 16, 24, 4, 12, 20, 2, 6, 10, 14, 18, 22)
    _ATTEMPT_PARTIAL = True

    def __init__(
        self,
        raw: Param[bool, Arg.Switch('-r', group='MODE', help='Use raw (no container) format.')] = False,
        alone: Param[bool, Arg.Switch('-a', group='MODE', help='Use the lzma container format.')] = False,
        xz: Param[bool, Arg.Switch('-x', group='MODE', help='Use the default xz format.')] = False,
        level: Param[int, Arg.Number('-l', bound=(0, 9), help='The compression level preset; between 0 and 9.')] = 9,
        delta: Param[int, Arg.Number('-d', help='Add a delta filter when compressing.')] = 0,
    ):
        if (raw, alone, xz).count(True) > 1:
            raise ValueError('Only one container format can be enabled.')
        if level not in range(10):
            raise ValueError('Compression level must be a number between 0 and 9.')
        super().__init__(filter=filter, raw=raw, alone=alone, xz=xz, delta=delta,
            level=level | PRESET_EXTREME)

    def reverse(self, data):
        filters = []
        if self.args.delta > 0:
            self.log_debug('adding delta filter')
            filters.append({'id': FILTER_DELTA, 'dist': self.args.delta})
        if self.args.alone:
            self.log_debug('setting alone format')
            mode = FORMAT_ALONE
            filters.append({'id': FILTER_LZMA1, 'preset': self.args.level})
        elif self.args.raw:
            self.log_debug('setting raw format')
            mode = FORMAT_RAW
            filters.append({'id': FILTER_LZMA2, 'preset': self.args.level})
        else:
            if not self.args.xz:
                self.log_info('choosing default .xz container format for compression')
            mode = FORMAT_XZ
            filters.append({'id': FILTER_LZMA2, 'preset': self.args.level})
        lz = LZMACompressor(mode, filters=filters)
        output = lz.compress(data)
        output += lz.flush()
        return output

    def _decompress(self, data: buf, lz: LZMADecompressor, partial: bool = False):
        temp = bytearray()
        sizes = repeat(1) if partial else [len(data)]
        with MemoryFile(temp) as output:
            with MemoryFile(data) as stream:
                for size in sizes:
                    if stream.eof or stream.closed:
                        break
                    offset = stream.tell()
                    try:
                        output.write(lz.decompress(stream.read(size)))
                    except (EOFError, LZMAError) as e:
                        raise RefineryPartialResult(
                            F'Compression failed at offset {offset}: {e!s}', temp)
        if n := len(lz.unused_data):
            raise RefineryPartialResult(F'Data stream is truncated, {n} bytes unused.', temp)
        return temp

    def _process(self, data: bytearray, partial=False):
        try:
            dc = LZMADecompressor()
            return self._decompress(data, dc, partial)
        except RefineryPartialResult as pe:
            best = pe
        except Exception:
            best = None
            self.log_info('default LZMA decompressor failed, brute-forcing custom header')
        view = memoryview(data)
        min_original_size = {
            # https://sourceforge.net/p/sevenzip/discussion/45797/thread/b6bd62f8/
            1: int((len(data) - 64_000) / 1.100), # noqa
            2: int((len(data) -  1_000) / 1.001), # noqa
        }
        for (version, p), offset_prop, to_data in product(
            ((1, 5),
             (2, 1)),
            self._SEARCH_SKIP1,
            self._SEARCH_SKIP2,
        ):
            offset = offset_prop + p + to_data
            if offset_prop + to_data > p + 20:
                # expect no more than a 20 byte header on top of the properties
                # that would be enough for, e.g. compressed & uncompressed size
                # each filling a full 64bit integer and 4 additional bytes.
                continue
            try:
                filter = parse_lzma_properties(
                    view[offset_prop:offset_prop + p],
                    version,
                    min_dict=self._SEARCH_MIN_DICT,
                    max_dict=self._SEARCH_MAX_DICT,
                )
                self.log_debug(F'attempt LZMA{version} at {offset_prop:02d}, skipping {to_data:02d}, filter: {filter!r}')
                engine = LZMADecompressor(FORMAT_RAW, filters=[filter])
                result = self._decompress(view[offset:], engine, partial)
            except RefineryPartialResult as pe:
                if best is None:
                    best = pe
                elif len(best.partial) < len(pe.partial):
                    best = pe
                continue
            except Exception:
                continue
            if buffer_contains(view[:offset], len(result).to_bytes(8, 'little')):
                self.log_debug('header contains uncompressed size, fast-tracking result')
            else:
                if len(result) < min_original_size[version]:
                    continue
                if len(result) * self._SEARCH_MAX_BLOW < len(data):
                    continue
            self.log_info(
                F'success with LZMA{version} properties at {offset_prop} and raw stream starting at {to_data + offset_prop + p}')
            return result
        if partial or not self._ATTEMPT_PARTIAL:
            if best and len(best.partial) > 0:
                raise best
            raise ValueError('unable to find an LZMA stream')

    def process(self, data: bytearray):
        if out := self._process(data):
            return out
        return self._process(data, partial=True)

    @classmethod
    def handles(cls, data):
        if len(data) < 4:
            return
        if data[:3] == B'\x5D\0\0':
            for lb in range(8):
                if data[3] == 1 << lb:
                    return True
        if data[:5] == B'\xFD7zXZ':
            return True


class _auto_decompress_lzma(lzma):
    _SEARCH_MIN_DICT = 0x1_0000
    _SEARCH_MAX_DICT = 0x100_0000
    _SEARCH_MAX_BLOW = 1.5
    _SEARCH_SKIP1 = (0,)
    _SEARCH_SKIP2 = (0, 8, 16, 4)
    _ATTEMPT_PARTIAL = False
