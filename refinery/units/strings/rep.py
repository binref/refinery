#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from itertools import repeat

from .. import arg, Unit


class rep(Unit):
    """
    Duplicates the given input a given number of times.
    """

    def __init__(self, count: arg(help='Defines the number of outputs for each input. The default is the minimum of 2.') = 2):
        super().__init__(count=count)

    def process(self, data: bytes):
        if self.args.count < 2:
            raise ValueError('The count must be at least two.')
        yield from repeat(data, self.args.count)
