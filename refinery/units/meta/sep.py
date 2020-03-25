#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import arg, Unit


class sep(Unit):
    """
    Multiple inputs are joined along a specified separator. If any of the input
    `refinery.lib.frame.Chunk`s is currently out of scope, `refinery.sep` turns
    makes them visible by default. This can be prevented by using the `-s` flag.
    """

    def __init__(
        self, separator: arg.help('Separator; the default is a line break.') = B'\n',
        scoped: arg.switch('-s', help=(
            'Maintain chunk scope; i.e. do not turn all input chunks visible.')) = False
    ):
        super().__init__(separator=separator, scoped=scoped)
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
