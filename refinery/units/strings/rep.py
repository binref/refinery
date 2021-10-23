#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from itertools import repeat

from refinery.units import arg, Unit


class rep(Unit):
    """
    Duplicates the given input a given number of times.
    """

    def __init__(self, count: arg(help='Defines the number of outputs for each input. The default is the minimum of 2.') = 2):
        super().__init__(count=count)

    def process(self, data: bytes):
        if self.args.count < 2:
            raise ValueError('The count must be at least two.')
        squeeze = self.args.squeeze
        if not squeeze:
            framestate = self._framed
            if not framestate:
                squeeze = True
            elif framestate.framebreak:
                self.log_debug('all repeated items will be joined with line breaks')
                yield B'\n'.join(repeat(data, self.args.count))
                return
            elif framestate.unframed:
                squeeze = True
        if not squeeze:
            self.log_debug('emitting each repeated item as an individual chunk')
            yield from repeat(data, self.args.count)
        else:
            self.log_debug('compressing all repeated items into a single chunk')
            yield data * self.args.count
