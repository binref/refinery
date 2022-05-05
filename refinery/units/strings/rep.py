#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from itertools import repeat

from refinery.units import Arg, Unit


class rep(Unit):
    """
    Duplicates the given input a given number of times. It is also possible to specify
    an iterable instead of a number, in which case the input will be replicated once for
    each item in this iterable.
    """

    def __init__(
        self,
        count: Arg.NumSeq(help=(
            'Defines the number of outputs to generate for each input. The default is {default}. '
            'You can specify any multibin expression that defines an integer iterable here: Each '
            'input chunk will be replicated once for each element of that sequence.')) = 2,
        label: Arg(type=str, help=(
            'If specified, the meta variable with this name will be populated with the index of '
            'the replicated chunk. When the count parameter is an integer, this label will be '
            'equivalent to the index meta variable.')) = None
    ):
        super().__init__(count=count, label=label)

    def process(self, data: bytes):
        def count():
            count = self.args.count
            if isinstance(count, int):
                return count
            return sum(1 for _ in count)

        if self.args.squeeze or not self._framed:
            self.log_debug('compressing all repeated items into a single chunk')
            yield data * count()
            return

        self.log_debug('emitting each repeated item as an individual chunk')

        label = self.args.label
        if label is None:
            yield from repeat(data, count())
            return

        meta = {}
        for counter in self.args.count:
            meta[label] = counter
            yield self.labelled(data, **meta)
