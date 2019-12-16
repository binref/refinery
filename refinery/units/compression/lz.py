#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import lzma as lzma_

from .. import Unit
from ...lib.argformats import number, OptionFactory, extract_options


class lzma(Unit):
    """
    LZMA compression and decompression.
    """

    def interface(self, argp):
        mode = argp.add_mutually_exclusive_group()
        mode.add_argument('-r', '--raw',
            action='store_true', help='Use raw (no container) format.')
        mode.add_argument('-a', '--alone',
            action='store_true', help='Use the lzma container format.')
        mode.add_argument('-x', '--xz',
            action='store_true', help='Use the default xz format.')
        argp.add_argument('-l', '--level', type=number[0:9], action='store', default=9,
            help='compression level preset between 0 and 9')
        argp.add_argument('-D', '--delta', type=int, default=None, action='store',
            help='Add a delta filter when compressing.')

        filters = extract_options(lzma_, 'FILTER_')
        del filters['DELTA']

        argp.add_argument(
            'filter', nargs='?', type=OptionFactory(filters), choices=list(filters),
            default=None, metavar='FILTER', help=(
                'Specifies a bcj filter to be applied. Possible values '
                'are: {}'.format(', '.join(filters))
            )
        )

        return super().interface(argp)

    def __init__(self, *args, **kw):
        super().__init__(*args, **kw)
        self.args.level |= lzma_.PRESET_EXTREME

    def _get_lz_mode_and_filters(self, reverse=False):
        mode = lzma_.FORMAT_AUTO
        filters = []
        if self.args.filter is not None:
            filters.append({'id': self.args.filter.value})
        if self.args.delta is not None:
            filters.append({
                'id': lzma_.FILTER_DELTA,
                'dist': self.args.delta
            })
        if self.args.alone:
            mode = lzma_.FORMAT_ALONE
            filters.append({
                'id': lzma_.FILTER_LZMA1,
                'preset': self.args.level
            })
        elif self.args.raw:
            mode = lzma_.FORMAT_RAW
            filters.append({
                'id': lzma_.FILTER_LZMA2,
                'preset': self.args.level
            })
        elif self.args.xz or reverse:
            if reverse:
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
