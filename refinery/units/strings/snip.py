#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from refinery.units import Arg, Unit


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
        length: Arg.Switch('-l', help=(
            'Interpret the end of a slice as a length rather than as an offset.')) = False,
        stream: Arg.Switch('-s', help=(
            'After each slice, consider only the data that follows after it for subsequent '
            'slicing.')) = False,
        remove: Arg.Switch('-r', help=(
            'Remove the slices from the input rather than selecting them.')) = False,
    ):
        super().__init__(slices=slices, length=length, stream=stream, remove=remove)

    def process(self, data: bytearray):
        slices: list[slice] = list(self.args.slices)
        stream = self.args.stream
        remove = self.args.remove
        length = self.args.length
        cursor = 0
        view = memoryview(data)

        for k, bounds in enumerate(slices):
            upper = bounds.stop
            lower = bounds.start or 0
            if upper is None:
                upper = len(data)
            else:
                upper += cursor
            if length:
                upper += lower
            bounds = slice(
                lower + cursor, upper, bounds.step)
            if stream:
                cursor = upper
            if not remove:
                temp = view[bounds]
            else:
                if k + 1 >= len(slices):
                    view.release()
                    del view
                    temp = data
                else:
                    temp = bytearray(data)
                del temp[bounds]
            yield temp
