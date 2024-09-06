#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units import Arg, Unit
from refinery.lib.argformats import DelayedBinaryArgument


class loop(Unit):
    """
    Applies a given multibin suffix to the input chunk repeatedly. For example, the following
    command would carve the largest base64-encoded buffer from the input, decode it, and then
    decompress the result 20 times:

        emit data | loop 20 csd[b64]:zl

    Notably, the argument after the count is a suffix, which means that handlers are applied
    from left to right (not from right to left).
    """

    def __init__(
        self, count: Arg.Number(metavar='count', help='The number of repeated applications of the suffix.'),
        suffix: Arg(type=str, help='A multibin expression suffix.')
    ):
        super().__init__(count=count, suffix=suffix)

    def process(self, data):
        for _ in range(self.args.count):
            data[:] = DelayedBinaryArgument(self.args.suffix, reverse=True, seed=data)(data)
        return data
