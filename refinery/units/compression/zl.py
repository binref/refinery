#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import zlib
import itertools

from refinery.units import Arg, Unit, RefineryPartialResult
from refinery.lib.tools import exception_to_string


class zl(Unit):
    """
    ZLib compression and decompression.
    """

    def __init__(
        self,
        level  : Arg.Number('-l', bound=(0, 0X9), help='Specify a compression level between 0 and 9.') = 9,
        window : Arg.Number('-w', bound=(8, 0XF), help='Manually specify the window size between 8 and 15.') = 15,
        zlib_header: Arg.Switch('-z', group='MODE', help='Use a ZLIB header.') = False,
        gzip_header: Arg.Switch('-g', group='MODE', help='Use a GZIP header.') = False
    ):
        if zlib_header and gzip_header:
            raise ValueError('You can only specify one header type (ZLIB or GZIP).')
        return super().__init__(level=level, window=window, zlib_header=zlib_header, gzip_header=gzip_header)

    def _decompress_data(self, data, mode: int, step: int):
        zl = zlib.decompressobj(mode)
        memory = memoryview(data)
        result = bytearray()
        while not zl.eof:
            read = min(step, len(memory))
            try:
                chunk = zl.decompress(memory[:read])
            except zlib.error as e:
                raise RefineryPartialResult(exception_to_string(e), result) from e
            else:
                result.extend(chunk)
                consumed = read - len(zl.unused_data)
                if not memory or consumed == 0:
                    break
                memory = memory[consumed:]
        return result, memory

    def process(self, data):
        if data[0] == 0x78 or data[0:2] == B'\x1F\x8B' or self.args.zlib_header or self.args.gzip_header:
            modes = [self.args.window | 0x20, -self.args.window]
        else:
            modes = [-self.args.window, self.args.window | 0x20]
        modes.extend([0x10 | self.args.window, 0])
        view = memoryview(data)
        step = 32 if self.leniency > 0 else len(data)
        for k in itertools.count(1):
            error = None
            rest = view
            for mode in modes:
                try:
                    out, rest = self._decompress_data(view, mode, step)
                except Exception as e:
                    error = error or e
                else:
                    self.log_info(F'used mode {mode} to decompress chunk {k}')
                    yield out
                    error = None
                    break
            if error:
                raise error
            if not rest:
                break
            if len(rest) == len(view):
                break
            if len(rest) > len(view):
                raise RuntimeError('Decompressor returned more tail data than input data.')
            yield out
            view = rest
        if k <= 0:
            raise ValueError('Could not detect any zlib stream.')

    def reverse(self, data):
        mode = -self.args.window
        if self.args.zlib_header:
            mode = -mode
        if self.args.gzip_header:
            mode = -mode | 0x10
        self.log_debug(F'using mode {mode:+2d} for compression')
        zl = zlib.compressobj(self.args.level, zlib.DEFLATED, mode)
        zz = zl.compress(data)
        return zz + zl.flush(zlib.Z_FINISH)

    @classmethod
    def handles(self, data: bytearray):
        for sig in (
            B'\x1F\x8B',  # gzip header
            B'\x78\x01',  # zlib low compression
            B'\x78\x9C',  # zlib medium compression
            B'\x78\xDA',  # zlib high compression
        ):
            if data[:2] == sig:
                return True
