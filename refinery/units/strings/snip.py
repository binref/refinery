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
            'slicing. This mode is incompatible with negative step sizes.')) = False,
        remove: Arg.Switch('-r', help=(
            'Remove the slices from the input rather than selecting them.')) = False,
    ):
        super().__init__(slices=slices, length=length, stream=stream, remove=remove)

    def process(self, data: bytearray):
        slices: list[slice] = list(self.args.slices)
        opt_stream = self.args.stream
        opt_remove = self.args.remove
        opt_length = self.args.length
        view = memoryview(data)
        offset = 0

        if opt_stream and any(b.step or 1 < 0 for b in slices):
            raise RuntimeError('Streaming is incompatible with negative step slices.')

        for k, bounds in enumerate(slices):
            step = bounds.step or 1
            stop = bounds.stop
            start = bounds.start
            if opt_length:
                if stop is not None:
                    if start is None:
                        if step < 0:
                            stop += len(data)
                    else:
                        stop += start
            if opt_stream:
                start = start or 0
                stop = stop or len(data)
                start += offset
                stop += offset

            bounds = slice(start, stop, bounds.step)

            if not opt_remove:
                temp = view[bounds]
            else:
                temp = bytearray(data)
                del temp[bounds]
            yield temp

            if opt_stream:
                offset = stop
