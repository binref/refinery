#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib.types import INF
from refinery.units.meta import Arg, ConditionalUnit


class iffc(ConditionalUnit, docs='{0}{p}{1}'):
    """
    Filter incoming chunks depending on whether their size is within the given bounds.
    """
    def __init__(
        self,
        bounds: Arg.Bounds(help='Specifies the (inclusive) range to check for.'),
        retain=False,
    ):
        super().__init__(
            bounds=bounds,
            retain=retain,
        )

    def match(self, chunk):
        length: int = len(chunk)
        bounds: slice = self.args.bounds
        a = bounds.start or 0
        b = bounds.stop or INF
        t = bounds.step or 1
        return a <= length <= b and not (length - a) % t
