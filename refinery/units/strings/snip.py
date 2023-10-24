#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from copy import copy

from refinery.units import Arg, Unit
from refinery.lib.tools import lookahead


class snip(Unit):
    """
    Snips the input data based on a Python slice expression. For example, the
    initialization `slice 0::1 1::1` would yield a unit that first extracts
    every byte at an even position and then, every byte at an odd position. In
    this case, multiple outputs are produced. The unit can be used in reverse
    mode, in which case the specified ranges are deleted sequentially from the
    input.
    """
    def __init__(
        self,
        slices: Arg(help='Specify start:stop:step in Python slice syntax.') = [slice(None, None)],
        length: Arg.Switch('-l',
            help='Interpret the end of a slice as a length rather than as an offset.') = False,
        remove: Arg.Switch('-r',
            help='Remove the slices from the input rather than selecting them.') = False,
    ):
        super().__init__(slices=slices, length=length, remove=remove)

    def process(self, data: bytearray):
        slices: list[slice] = list(self.args.slices)
        if self.args.length:
            for k, s in enumerate(slices):
                if s.stop is None:
                    continue
                slices[k] = slice(s.start, (s.start or 0) + s.stop, s.step)
        if self.args.remove:
            for last, bounds in lookahead(slices):
                chunk = data if last else copy(data)
                del chunk[bounds]
                yield chunk
        else:
            for bounds in slices:
                yield data[bounds]
