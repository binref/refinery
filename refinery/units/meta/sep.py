#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import Unit
from ...lib.argformats import DelayedBinaryArgument


class sep(Unit):
    """
    Multiple inputs are joined along a specified separator. If any of the input
    `refinery.lib.frame.Chunk`s is currently out of scope, `refinery.sep` turns
    makes them visible by default. This can be prevented by using the `-s` flag.
    """

    def interface(self, argp):
        argp.add_argument('-s', '--scoped', action='store_true',
            help='Prevent sep from automatically turning all input chunks visible.')
        argp.add_argument('separator', type=DelayedBinaryArgument, default=B'\n',
            nargs='?', help='Separator; the default is a line break.')
        return super().interface(argp)

    def __init__(self, *args, **kw):
        super().__init__(*args, **kw)
        self.separate = False

    def filter(self, inputs):
        it = iter(inputs)
        try:
            data = next(it)
        except StopIteration:
            return
        self.separate = True
        for upcoming in it:
            if not self.args.scoped:
                data.visible = True
            yield data
            data = upcoming
        self.separate = False
        yield data

    def process(self, data):
        yield data
        if self.separate:
            yield self.args.separator
