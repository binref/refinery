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

            def __str__(self):
                status = 'partial' if self.failed else 'success'
                prefix = self.prefix
                if prefix is not None:
                    prefix = F'0x{prefix:02X}'
                return F'prefix={prefix}, cutoff=0x{self.cutoff:02X}, [{status}] engine={self.engine.name}'

            def __len__(self):
                return len(self.result)

            @property
            def ratio(self):
                if not self.result:
                    return INF
                return len(data) / len(self.result)

            @property
            def unmodified(self):
                return self.cutoff == 0
                return self.prefix is None and self.cutoff == 0

            @property
            def method(self):
                return self.engine.name

        if self.args.prepend:
            buffer = bytearray(1 + len(data))
            buffer[1:] = data

        best_only_success: Optional[Decompression] = None
        best_with_failure: Optional[Decompression] = None

        def decompress(engine: Unit, cutoff: int = 0, prefix: Optional[int] = None):
            ingest = data[cutoff:]
            failed = True
            if prefix is not None:
                buffer[0] = prefix
                ingest = buffer
            if engine.handles(ingest) is False:
                return Decompression(engine, None, cutoff, prefix)
            try:
                result = engine.process(ingest)
            except RefineryPartialResult as pr:
                result = pr.partial
            except Exception:
                result = None
            else:
                failed = False
            return Decompression(engine, result, cutoff, prefix, failed)

        def update(new: Decompression, best: Optional[Decompression] = None, discard_if_too_good=False) -> Decompression:
            ratio = new.ratio
            if ratio > self.args.max_ratio:
                return best
            if ratio < self.args.min_ratio:
                return best
            prefix = new.prefix
            if prefix is not None:
                prefix = F'0x{prefix:02X}'
            r = 1 if new.unmodified and best and not best.unmodified else 0.95
            if not best or len(new) < len(best):
                q = 0
            else:
                q = ratio / best.ratio
            if q < r:
                if best and discard_if_too_good:
                    if q < 0.5:
                        return best
                    if new.failed:
                        return best
                self.log_info(lambda: F'obtained {ratio * 100:07.4f}% compression ratio [q={q:07.4f}] with: {new!s}')
                return new
            else:
                self.log_debug(F'obtained {ratio * 100:07.4f}% compression ratio [q={q:07.4f}] with: {new!s}')
                return best

        for engine in self.engines:
            self.log_debug(F'attempting engine: {engine.name}')
            careful = isinstance(engine, (lznt1, lzf, lzjb))
            for t in range(self.args.tolerance):
                if best_only_success and careful and t > 0:
                    break
                dc = decompress(engine, t)
                if not dc.failed:
                    best_only_success = update(dc, best_only_success, careful)
                else:
                    best_with_failure = update(dc, best_with_failure, careful)
            if self.args.prepend and not best_only_success:
                for p in range(0x100):
                    dc = decompress(engine, 0, p)
                    if not dc.failed:
                        best_only_success = update(dc, best_only_success, careful)
                    else:
                        best_with_failure = update(dc, best_with_failure, careful)

        if best_only_success is not None:
            return self.labelled(best_only_success.result, method=best_only_success.method)
        if best_with_failure is not None:
            self.log_info('the only decompression with result returned only a partial result.')
            return self.labelled(best_with_failure.result, method=best_with_failure.method)
        self.log_warn('no compression engine worked, returning original data.')
        return data
