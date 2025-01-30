#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from enum import IntFlag
from itertools import repeat, product

from lzma import (
    _decode_filter_properties,
    FILTER_DELTA,
    FILTER_LZMA1,
    FILTER_LZMA2,
    FORMAT_ALONE,
    FORMAT_RAW,
    FORMAT_XZ,
    LZMACompressor,
    LZMADecompressor,
    LZMAError,
    PRESET_EXTREME,
)

from refinery.units import Arg, Unit, RefineryPartialResult
from refinery.lib.structures import MemoryFile

__all__ = ['lzma']


class F(IntFlag):
    DEFAULT = 0
    INJECT = 1
    STEPWISE = 2


class lzma(Unit):
    """
    LZMA compression and decompression.
    """
    def __init__(
        self,
        raw   : Arg.Switch('-r', group='MODE', help='Use raw (no container) format.') = False,
        alone : Arg.Switch('-a', group='MODE', help='Use the lzma container format.') = False,
        xz    : Arg.Switch('-x', group='MODE', help='Use the default xz format.') = False,
        level : Arg.Number('-l', bound=(0, 9), help='The compression level preset; between 0 and 9.') = 9,
        delta : Arg.Number('-d', help='Add a delta filter when compressing.') = None,
    ):
        if (raw, alone, xz).count(True) > 1:
            raise ValueError('Only one container format can be enabled.')
        if level not in range(10):
            raise ValueError('Compression level must be a number between 0 and 9.')
        super().__init__(filter=filter, raw=raw, alone=alone, xz=xz, delta=delta,
            level=level | PRESET_EXTREME)

    def reverse(self, data):
        filters = []
        if self.args.delta is not None:
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

    def _decompress(self, data: bytearray, lz: LZMADecompressor, partial: bool = False):
        temp = bytearray()
        sizes = repeat(1) if partial else [len(data)]
        with MemoryFile(temp) as output:
            with MemoryFile(data) as stream:
                for size in sizes:
                    if stream.eof or stream.closed:
                        break
                    try:
                        offset = stream.tell()
                        output.write(lz.decompress(stream.read(size)))
                    except (EOFError, LZMAError):
                        raise RefineryPartialResult(
                            F'compression failed at offset {offset}', temp)
        return temp

    def _process(self, data: bytearray, partial=False):
        try:
            dc = LZMADecompressor()
            return self._decompress(data, dc, partial)
        except RefineryPartialResult as pe:
            best_partial_result = pe
        except Exception:
            best_partial_result = None
            self.log_info('default LZMA decompressor failed, brute-forcing custom header')
        modes = [
            ('LZMA1', FILTER_LZMA1, 5),
            ('LZMA2', FILTER_LZMA2, 1),
        ]
        view = memoryview(data)
        for (name, mode, p), n, skipped in product(modes, range(16), range(16)):
            try:
                fp = _decode_filter_properties(mode, view[n:n + p])
                engine = LZMADecompressor(FORMAT_RAW, filters=[fp])
                result = self._decompress(view[n + p + skipped:], engine, partial)
            except RefineryPartialResult as pe:
                if best_partial_result is None:
                    best_partial_result = pe
                elif len(best_partial_result.partial) < len(pe.partial):
                    best_partial_result = pe
                continue
            except Exception:
                continue
            if len(result) * 1.2 < len(data):
                continue
            self.log_info(F'detected properties for {name} at {n}, raw stream starting at offset {skipped}')
            return result
        if partial and best_partial_result is not None:
            raise best_partial_result

    def process(self, data: bytearray):
        if out := self._process(data):
            return out
        return self._process(data, partial=True)

    @classmethod
    def handles(self, data: bytearray):
        if data[:4] == B'\x5D\0\0\0':
            return True
        if data[:5] == B'\xFD7zXZ':
            return True
