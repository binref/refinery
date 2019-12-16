#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import Unit
from ...lib.argformats import number


class rep(Unit):
    """
    Duplicates the given input a given number of times.
    """

    def interface(self, argp):
        argp.add_argument('count', type=number[1:], nargs='?', default=2,
            help='Defines the number of outputs for each input. The default is 2.')
        return super().interface(argp)

    def process(self, data: bytes):
        from itertools import repeat
        yield from repeat(data, self.args.count)
