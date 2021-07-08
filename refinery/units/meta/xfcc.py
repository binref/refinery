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
    def __init__(
        self,
        variable: arg(help='The variable which is used as the accumulator') = 'count',
        relative: arg.switch('-r', help='Normalize the accumulator to a number between 0 and 1.') = False
    ):
        super().__init__(variable=variable, relative=relative)
        self._trunk = None
        self._store = collections.defaultdict(int)

    def finish(self):
        if self.args.relative and self._store:
            maximum = max(self._store.values())
        for k, (chunk, count) in enumerate(self._store.items()):
            if self.args.relative:
                count /= maximum
            chunk._meta[self.args.variable] = count
            chunk._path = chunk.path[:-2] + (0, k)
            yield chunk
        self._store.clear()

    def _getcount(self, chunk):
        try:
            count = int(chunk.meta[self.args.variable])
        except (AttributeError, KeyError, TypeError):
            return 1
        else:
            return count

    def filter(self, chunks):
        it = iter(chunks)
        try:
            head = next(it)
        except StopIteration:
            return
        if len(head.path) < 2:
            self.log_warn(F'the current frame is nested {len(head.path)} layers deep, at least two layers are required.')
            yield head
            for item in it:
                self.log_debug(repr(item))
                yield item
            return
        trunk = head.path[:-2]
        store = self._store
        if trunk != self._trunk:
            yield from self.finish()
            self._trunk = trunk
        store[head] += self._getcount(head)
        for chunk in it:
            store[chunk] += self._getcount(chunk)
