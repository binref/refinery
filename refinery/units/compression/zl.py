#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import zlib

from .. import arg, Unit


class zl(Unit):
    """
    ZLib compression and decompression.
    """

    def __init__(
        self,
        level  : arg.number('-l', bound=(0, 0X9), help='Specify a compression level between 0 and 9.') = 9,
        window : arg.number('-w', bound=(8, 0XF), help='Manually specify the window size between 8 and 15.') = 15,
        force  : arg.switch('-f', help='Decompress as far as possible, even if all known methods fail.') = False,
        zlib_header: arg.switch('-z', group='MODE', help='Use a ZLIB header.') = False,
        gzip_header: arg.switch('-g', group='MODE', help='Use a GZIP header.') = False
    ):
        if zlib_header and gzip_header:
            raise ValueError('You can only specify one header type (ZLIB or GZIP).')
        return super().__init__(level=level, window=window, force=force, zlib_header=zlib_header, gzip_header=gzip_header)

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
