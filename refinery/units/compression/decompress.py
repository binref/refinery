#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import arg, Unit, RefineryPartialResult
from ...lib.types import INF

from .ap import aplib
from .bz2 import bz2
from .lz import lzma
from .lznt1 import lznt1
from .zl import zl
from .lz4 import lz4
from .blz import blz


class decompress(Unit):
    """
    Attempts all available decompression units against the input and returns
    the output of the first successful one. If none succeeds, the data is
    returned unaltered. The process is heavily biased against LZNT1 decompression
    due to a large tendency for LZNT1 false positives.
    """
    def __init__(
        self,
        prepend: arg.switch('-P', '--no-prepend', off=True, help=(
            'By default, if decompression fails, the unit attempts to prefix '
            'the data with all possible values of a single byte and decompress '
            'the result. This behavior can be disabled with this flag.')
        ) = True,
        tolerance: arg.number('-t', help=(
            'Maximum number of bytes to strip from the beginning of the data; '
            'The default value is 12.')
        ) = 12,
        min_ratio: arg('-r', metavar='R', help=(
            'To determine whether a decompression algorithm was successful, the '
            'ratio of compressed size to decompressed size is required to be at '
            'least this number, a floating point value R; default value is 1.')
        ) = 1,
    ):
        if min_ratio <= 0:
            raise ValueError('The compression factor must be nonnegative.')
        super().__init__(tolerance=tolerance, prepend=prepend, min_ratio=min_ratio)
        self.engines = [
            engine() for engine in [zl, lzma, aplib, bz2, blz, lz4, lznt1]
        ]

    def process(self, data):
        best = None
        current_ratio = 1

        class result:
            unit = self

            def __init__(self, engine, cutoff=0, prefix=None):
                feed = data

                self.engine = engine
                self.prefix = prefix
                self.cutoff = cutoff

                if cutoff:
                    feed = data[cutoff:]
                if prefix is not None:
                    feed = prefix + data

                try:
                    self.result = engine.process(feed)
                except RefineryPartialResult as pr:
                    self.result = pr.partial
                except Exception:
                    self.result = B''

                if not self.result:
                    self.ratio = INF
                else:
                    self.ratio = len(data) / len(self.result)

            @property
            def unmodified(self):
                return not self.prefix and not self.cutoff

            def schedule(self):
                nonlocal best, current_ratio
                if self.ratio >= self.unit.args.min_ratio:
                    return
                prefix = hex(self.prefix[0]) if self.prefix else None
                r = 1 if self.unmodified and best and not best.unmodified else 0.9
                if self.engine.__class__ is lznt1:
                    r /= 2
                if not best or self.ratio / current_ratio < r:
                    self.unit.log_info(lambda: (
                        F'obtained {self.ratio:.2f} compression ratio with: prefix={prefix}, '
                        F'cutoff={self.cutoff}, engine={self.engine.name}'))
                    best = self
                    current_ratio = self.ratio

        for engine in self.engines:
            for t in range(self.args.tolerance):
                result(engine, t).schedule()
            if self.args.prepend:
                for p in range(0x100):
                    result(engine, 0, bytes((p,))).schedule()

        if best is None:
            self.log_info('nothing worked, returning original data.')
            return data

        return best.result
