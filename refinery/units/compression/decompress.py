#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import ByteString, List, NamedTuple, Optional

from refinery.units import Arg, Unit, RefineryPartialResult
from refinery.lib.types import INF

from .ap     import aplib  # noqa
from .blz    import blz    # noqa
from .bz2    import bz2    # noqa
from .jcalg  import jcalg  # noqa
from .lz     import lzma   # noqa
from .lz4    import lz4    # noqa
from .lzjb   import lzjb   # noqa
from .lznt1  import lznt1  # noqa
from .lzo    import lzo    # noqa
from .szdd   import szdd   # noqa
from .zl     import zl     # noqa
from .qlz    import qlz    # noqa
from .lzf    import lzf    # noqa
from .lzw    import lzw    # noqa


class decompress(Unit):
    """
    Attempts all available decompression units against the input and returns
    the output of the first successful one. If none succeeds, the data is
    returned unaltered. The process is heavily biased against LZNT1 decompression
    due to a large tendency for LZNT1 false positives.
    """
    def __init__(
        self,
        prepend: Arg.Switch('-P', '--no-prepend', off=True, help=(
            'By default, if decompression fails, the unit attempts to prefix '
            'the data with all possible values of a single byte and decompress '
            'the result. This behavior can be disabled with this flag.')
        ) = True,
        tolerance: Arg.Number('-t', help=(
            'Maximum number of bytes to strip from the beginning of the data; '
            'The default value is 12.')
        ) = 12,
        max_ratio: Arg('-m', metavar='R', help=(
            'To determine whether a decompression algorithm was successful, the '
            'ratio of compressed size to decompressed size may at most be as large '
            'as this number, a floating point value R; default value is {default}.')
        ) = 1,
        min_ratio: Arg('-n', metavar='R', help=(
            'Require that compression ratios must be at least as large as R. This '
            'is a "too good to be true" heuristic against algorithms like lznt1 '
            'that can produce false positives. The default is {default}.')
        ) = 0.0001,
    ):
        if min_ratio <= 0:
            raise ValueError('The compression factor must be nonnegative.')
        super().__init__(
            tolerance=tolerance,
            prepend=prepend,
            min_ratio=min_ratio,
            max_ratio=max_ratio
        )
        self.engines: List[Unit] = [
            engine.assemble() for engine in [
                szdd, zl, lzma, aplib, qlz, lzf, lzw, jcalg, bz2, blz, lzjb, lz4, lzo, lznt1]
        ]
        for engine in self.engines:
            engine.log_detach()

    def process(self, data):

        data = memoryview(data)

        class Decompression(NamedTuple):
            engine: Unit
            result: Optional[ByteString] = None
            cutoff: int = 0
            prefix: Optional[int] = None
            failed: bool = False

            @property
            def ratio(self):
                if not self.result:
                    return INF
                return len(data) / len(self.result)

            @property
            def unmodified(self):
                return self.prefix is None and self.cutoff == 0

            @property
            def method(self):
                return self.engine.name

        if self.args.prepend:
            buffer = bytearray(1 + len(data))
            buffer[1:] = data

        best: Optional[Decompression] = None

        def decompress(engine: Unit, cutoff: int = 0, prefix: Optional[int] = None):
            ingest = data[cutoff:]
            failed = False
            if prefix is not None:
                buffer[0] = prefix
                ingest = buffer
            if engine.handles(ingest) is False:
                return Decompression(engine, None, cutoff, prefix)
            try:
                result = engine.process(ingest)
            except RefineryPartialResult as pr:
                result = pr.partial
                failed = True
            except Exception as error:
                self.log_debug(F'error from {engine.name}: {error!s}')
                result = None
            return Decompression(engine, result, cutoff, prefix, failed)

        def update(new: Decompression, discard_if_too_good=False) -> Decompression:
            ratio = new.ratio
            if ratio > self.args.max_ratio:
                return best
            if ratio < self.args.min_ratio:
                return best
            prefix = new.prefix and hex(new.prefix)
            r = 1 if new.unmodified and best and not best.unmodified else 0.9
            q = best and ratio / best.ratio
            if not best or q < r:
                if best and discard_if_too_good:
                    if q < 0.5:
                        return best
                    if new.failed:
                        return best
                self.log_info(lambda: (
                    F'obtained {ratio:.2f} compression ratio with: prefix={prefix}, '
                    F'cutoff={new.cutoff}, engine={new.engine.name}'))
                return new
            else:
                return best

        for engine in self.engines:
            self.log_debug(F'attempting engine: {engine.name}')
            careful = isinstance(engine, lznt1)
            for t in range(self.args.tolerance):
                if best and careful and t > 0:
                    break
                best = update(decompress(engine, t), careful)
            if self.args.prepend and best and not careful:
                for p in range(0x100):
                    best = update(decompress(engine, 0, p), careful)

        if best is None:
            self.log_warn('no compression engine worked, returning original data.')
            return data
        else:
            return self.labelled(best.result, method=best.method)
