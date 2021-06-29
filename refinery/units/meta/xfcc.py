#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import collections

from .. import arg, Unit


class xfcc(Unit):
    """
    The cross frame chunk count unit! It computes the number of times a chunk occurs across several frames
    of input. It consumes all frames in the current and counts the number of times each item occurs. It
    converts a frame tree of depth 2 into a new frame tree of depth 2 where the parent of every leaf has
    this leaf as its only child. The leaves of this tree have been enriched with a meta variable containing
    the number of times the corresponding chunk has occurred in the input frame tree.
    """
    def __init__(self, variable: arg(help='The variable which is used as the accumulator') = 'count'):
        super().__init__(variable=variable)
        self._trunk = None
        self._store = collections.defaultdict(int)

    def finish(self):
        for k, (chunk, count) in enumerate(self._store.items()):
            chunk._meta[self.args.variable] = count
            chunk._path = chunk.path[:-2] + (0, k)
            yield chunk
        self._store.clear()

    def filter(self, chunks):
        it = iter(chunks)
        try:
            head = next(it)
        except StopIteration:
            return
        if len(head.path) < 2:
            raise ValueError('requires at least two of frame layers')
        trunk = head.path[:-2]
        store = self._store
        if trunk != self._trunk:
            yield from self.finish()
            self._trunk = trunk
        store[head] += 1
        for chunk in it:
            store[chunk] += 1
