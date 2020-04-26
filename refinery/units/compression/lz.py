#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import lzma as lzma_

from .. import arg, Unit
from ...lib.argformats import OptionFactory, extract_options

__all__ = ['lzma']


class lzma(Unit):
    """
    LZMA compression and decompression.
    """
    _LZMA_FILTER = extract_options(lzma_, 'FILTER_', 'DELTA')
    _LZMA_PARSER = OptionFactory(_LZMA_FILTER)

    def __init__(
        self, filter: arg.choice(choices=list(_LZMA_FILTER), metavar='FILTER', help=(
            'Specifies a bcj filter to be applied. Possible values are: {choices}')) = None,
        raw   : arg.switch('-r', group='MODE', help='Use raw (no container) format.') = False,
        alone : arg.switch('-a', group='MODE', help='Use the lzma container format.') = False,
        xz    : arg.switch('-x', group='MODE', help='Use the default xz format.') = False,
        level : arg.number('-l', bound=(0, 9), help='The compression level preset; between 0 and 9.') = 9,
        delta : arg.number('-d', help='Add a delta filter when compressing.') = None,
    ):
        filter = filter and self._LZMA_PARSER(filter)
        if (raw, alone, xz).count(True) > 1:
            raise ValueError('Only one container format can be enabled.')
        if level not in range(10):
            raise ValueError('Compression level must be a number between 0 and 9.')
        super().__init__(filter=filter, raw=raw, alone=alone, xz=xz, delta=delta,
            level=level | lzma_.PRESET_EXTREME)

    def _get_lz_mode_and_filters(self, reverse=False):
        mode = lzma_.FORMAT_AUTO
        filters = []
        if self.args.filter is not None:
            filters.append({'id': self.args.filter.value})
        if self.args.delta is not None:
            self.log_debug('adding delta filter')
            filters.append({
                'id': lzma_.FILTER_DELTA,
                'dist': self.args.delta
            })
        if self.args.alone:
            self.log_debug('setting alone format')
            mode = lzma_.FORMAT_ALONE
            filters.append({
                'id': lzma_.FILTER_LZMA1,
                'preset': self.args.level
            })
        elif self.args.raw:
            self.log_debug('setting raw format')
            mode = lzma_.FORMAT_RAW
            filters.append({
                'id': lzma_.FILTER_LZMA2,
                'preset': self.args.level
            })
        elif self.args.xz or reverse:
            if reverse and not self.log_debug('setting xz container format'):
                self.log_info('choosing default .xz container format for compression.')
            mode = lzma_.FORMAT_XZ
            filters.append({
                'id': lzma_.FILTER_LZMA2,
                'preset': self.args.level
            })
        return mode, filters

    def reverse(self, data):
        mode, filters = self._get_lz_mode_and_filters(True)
        lz = lzma_.LZMACompressor(mode, filters=filters)
        output = lz.compress(data)
        output += lz.flush()
        return output

    def process(self, data):
        keywords = {}
        mode, filters = self._get_lz_mode_and_filters(False)
        if self.args.raw:
            keywords['filters'] = filters
        lz = lzma_.LZMADecompressor(mode, **keywords)
        return lz.decompress(data)
