#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from copy import copy

from .. import arg, Unit
from ...lib.tools import lookahead


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
        slices: arg(help='Specify start:stop:step in Python slice syntax.') = [slice(None, None)],
        remove: arg.switch('-r', help='Remove the slices from the input rather than selecting them.') = False
    ):
        super().__init__(slices=slices, remove=remove)

    def process(self, data: bytearray):
        if self.args.remove:
            for last, bounds in lookahead(self.args.slices):
                chunk = data if last else copy(data)
                del chunk[bounds]
                yield chunk
        else:
            for bounds in self.args.slices:
                yield data[bounds]
