#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import zlib

from .. import Unit
from ...lib.argformats import number


class zl(Unit):
    """
    ZLib compression and decompression.
    """

    def interface(self, argp):
        argp.add_argument('-l', '--level', action='store', type=number[0:9], default=9,
            help='specify level manually')
        argp.add_argument('-w', '--window', action='store', type=number[8:15], default=15,
            help='manually specify window size (but why.)')
        argp.add_argument('-f', '--force', action='store_true', help='decompress even if all known methods fail')
        mode = argp.add_mutually_exclusive_group()
        mode.add_argument('-z', '--zlib-header', action='store_true', help='use a zlib header')
        mode.add_argument('-g', '--gzip-header', action='store_true', help='use a gzip header')
        return super().interface(argp)

    def _force_decompress(self, data, mode):
        z = zlib.decompressobj(mode)

        def as_many_as_possible():
            for k in range(len(data)):
                try: yield z.decompress(data[k : k + 1])
                except zlib.error: break

        return B''.join(as_many_as_possible())

    def process(self, data):
        if data[0] == 0x78 or data[0:2] == B'\x1F\x8B' or self.args.zlib_header or self.args.gzip_header:
            mode_candidates = [self.args.window | 0x20, -self.args.window, 0]
        else:
            mode_candidates = [-self.args.window, self.args.window | 0x20, 0]
        for mode in mode_candidates:
            self.log_info(F'using mode {mode:+2d} for decompression')
            try:
                z = zlib.decompressobj(mode)
                return z.decompress(data)
            except zlib.error:
                pass
        if self.args.force:
            return self._force_decompress(data, mode_candidates[0])
        raise ValueError('could not detect any zlib stream.')

    def reverse(self, data):
        mode = -self.args.window
        if self.args.zlib_header:
            mode = -mode
        if self.args.gzip_header:
            mode = -mode | 0x10
        self.log_info(F'using mode {mode:+2d} for compression')
        zl = zlib.compressobj(self.args.level, zlib.DEFLATED, mode)
        zz = zl.compress(data)
        return zz + zl.flush(zlib.Z_FINISH)
