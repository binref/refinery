#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import Unit


class intersection(Unit):
    """
    This unit can be used to compute the intersection of several frames of input chunks. It consumes all
    frames in the current layer, interprets each as a set of input chunks, and computes their intersection.
    After the last frame is consumed, the unit outputs one frame containing the result. Consequently, the
    unit can only be used in frames that are nested at least two layers deep; otherwise, there is nothing
    to intersect.
    """
    def __init__(self):
        super().__init__()
        self._trunk = None
        self._storage = ()

    def finish(self):
        yield from self._storage

    def filter(self, chunks):
        it = iter(chunks)
        try:
            head = next(it)
        except StopIteration:
            return
        if len(head.path) < 2:
            raise ValueError('requires at least two of frame layers')
        trunk = head.path[:-2]
        storage = self._storage
        if trunk != self._trunk:
            self._storage = set(it)
            self._storage.add(head)
            self._trunk = trunk
            yield from storage
        else:
            def rewind():
                yield head
                yield from it
            storage.intersection_update(rewind())
