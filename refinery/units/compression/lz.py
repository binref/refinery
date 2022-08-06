#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import ByteString, List
from enum import IntFlag
from itertools import repeat

import lzma as std_lzma

from refinery.units import Arg, Unit, RefineryPartialResult
from refinery.lib.argformats import OptionFactory, extract_options
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
    _LZMA_FILTER = extract_options(std_lzma, 'FILTER_', 'DELTA')
    _LZMA_PARSER = OptionFactory(_LZMA_FILTER)

    def __init__(
        self, filter: Arg.Choice(choices=list(_LZMA_FILTER), metavar='FILTER', help=(
            'Specifies a bcj filter to be applied. Possible values are: {choices}')) = None,
        raw   : Arg.Switch('-r', group='MODE', help='Use raw (no container) format.') = False,
        alone : Arg.Switch('-a', group='MODE', help='Use the lzma container format.') = False,
        xz    : Arg.Switch('-x', group='MODE', help='Use the default xz format.') = False,
        level : Arg.Number('-l', bound=(0, 9), help='The compression level preset; between 0 and 9.') = 9,
        delta : Arg.Number('-d', help='Add a delta filter when compressing.') = None,
    ):
        filter = filter and self._LZMA_PARSER(filter)
        if (raw, alone, xz).count(True) > 1:
            raise ValueError('Only one container format can be enabled.')
        if level not in range(10):
            raise ValueError('Compression level must be a number between 0 and 9.')
        super().__init__(filter=filter, raw=raw, alone=alone, xz=xz, delta=delta,
            level=level | std_lzma.PRESET_EXTREME)

    def _get_lz_mode_and_filters(self, reverse=False):
        mode = std_lzma.FORMAT_AUTO
        filters = []
        if self.args.filter is not None:
            filters.append({'id': self.args.filter.value})
        if self.args.delta is not None:
            self.log_debug('adding delta filter')
            filters.append({
                'id': std_lzma.FILTER_DELTA,
                'dist': self.args.delta
            })
        if self.args.alone:
            self.log_debug('setting alone format')
            mode = std_lzma.FORMAT_ALONE
            filters.append({
                'id': std_lzma.FILTER_LZMA1,
                'preset': self.args.level
            })
        elif self.args.raw:
            self.log_debug('setting raw format')
            mode = std_lzma.FORMAT_RAW
            filters.append({
                'id': std_lzma.FILTER_LZMA2,
                'preset': self.args.level
            })
        elif self.args.xz or reverse:
            if reverse and not self.log_debug('setting xz container format'):
                self.log_info('choosing default .xz container format for compression.')
            mode = std_lzma.FORMAT_XZ
            filters.append({
                'id': std_lzma.FILTER_LZMA2,
                'preset': self.args.level
            })
        return mode, filters

    def reverse(self, data):
        mode, filters = self._get_lz_mode_and_filters(True)
        lz = std_lzma.LZMACompressor(mode, filters=filters)
        output = lz.compress(data)
        output += lz.flush()
        return output

    def _process_stream(self, data: ByteString, strategy: F, keywords):
        if strategy & F.STEPWISE:
            sizes = repeat(1)
        else:
            sizes = [len(data)]
        lz = std_lzma.LZMADecompressor(**keywords)
        with MemoryFile() as output:
            with MemoryFile(data) as stream:
                if strategy & F.INJECT:
                    output.write(lz.decompress(stream.read(5)))
                    output.write(lz.decompress(B'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'))
                for size in sizes:
                    if stream.eof or stream.closed:
                        break
                    try:
                        position = stream.tell()
                        output.write(lz.decompress(stream.read(size)))
                    except (EOFError, std_lzma.LZMAError) as error:
                        msg = error.args[0] if len(error.args) == 1 else error.__class__.__name__
                        raise RefineryPartialResult(F'compression failed at offset {position}: {msg!s}',
                            output.getvalue())
            return output.getvalue()

    def process(self, data: bytearray):
        errors: List[RefineryPartialResult] = []
        view = memoryview(data)
        keywords = {}
        keywords['format'], filters = self._get_lz_mode_and_filters(False)
        if self.args.raw:
            keywords['filters'] = filters
        for strategy in (F.DEFAULT, F.INJECT, F.STEPWISE, F.INJECT | F.STEPWISE):
            try:
                return self._process_stream(view, strategy, keywords)
            except RefineryPartialResult as p:
                self.log_info(F'decompression failed with strategy {strategy}: {p.message}')
                errors.append(p)
        raise max(errors, key=lambda e: len(e.partial))

    @classmethod
    def handles(self, data: bytearray):
        if data[:4] == B'\x5D\0\0\0':
            return True
        if data[:5] == B'\xFD7zXZ':
            return True
