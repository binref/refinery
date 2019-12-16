#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import Unit
from ...lib.argformats import sliceobj


class snip(Unit):
    """
    Snips the input data based on a Python slice expression. For example,
    the initialization `slice 0::1 1::1` would yield a unit that first extracts
    every byte at an even position and then, every byte at an odd position. In
    this case, multiple outputs are produced.
    """
    def interface(self, argp):
        argp.add_argument(
            'slice',
            type=sliceobj,
            nargs='*',
            default=[slice(None, None)],
            help='Specify start:stop:step in Python slice syntax.'
        )
        return super().interface(argp)

    def process(self, data):
        for bounds in self.args.slice:
            yield data[bounds]
