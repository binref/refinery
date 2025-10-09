from __future__ import annotations

import itertools
import zlib

from refinery.lib.tools import exception_to_string
from refinery.lib.types import Param
from refinery.units import Arg, RefineryPartialResult, Unit


class zl(Unit):
    """
    ZLib compression and decompression.
    """

    def __init__(
        self,
        level: Param[int, Arg.Number('-l', bound=(0, 0X9), help='Specify a compression level between 0 and 9.')] = 9,
        window: Param[int, Arg.Number('-w', bound=(8, 0XF), help='Manually specify the window size between 8 and 15.')] = 15,
        zlib_header: Param[bool, Arg.Switch('-z', group='MODE', help='Use a ZLIB header.')] = False,
        gzip_header: Param[bool, Arg.Switch('-g', group='MODE', help='Use a GZIP header.')] = False
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
                if not result:
                    raise
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
        rest = view
        step = 32 if self.leniency > 0 else len(data)
        count = 0
        error = None
        for k in itertools.count(1):
            error = None
            for mode in modes:
                msg = F'decompressing chunk {k} with mode {mode & 0xFF:02X}'
                try:
                    out, rest = self._decompress_data(view, mode, step)
                    yield out
                except Exception as e:
                    self.log_info(F'{msg} failed: {e!s}')
                    error = error or e
                else:
                    self.log_info(F'{msg} ok, remaining data:', rest, clip=True)
                    count += 1
                    error = None
                    modes = [mode]
                    break
            if error or not rest or len(rest) == len(view):
                break
            if len(rest) > len(view):
                raise RuntimeError('Decompressor returned more tail data than input data.')
            view = rest
        if count <= 0:
            raise error or ValueError('Could not detect any zlib stream.')
        if rest:
            from refinery.lib.meta import SizeInt
            size = SizeInt(len(rest))
            raise RefineryPartialResult(F'{size!r} excess data after compressed stream', rest)

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
    def handles(cls, data):
        for sig in (
            B'\x1F\x8B',  # gzip header
            B'\x78\x01',  # zlib low compression
            B'\x78\x9C',  # zlib medium compression
            B'\x78\xDA',  # zlib high compression
        ):
            if data[:2] == sig:
                return True
