#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import arg
from . import FrameSlicer


class scope(FrameSlicer):
    """
    After using `refinery.scope` within in a `refinery.lib.frame`, all the
    following operations will be applied only to the selected indices. All
    remaining chunks still exist, they are just not operated on. When the
    frame closes or the frame is being rescoped by a second application of
    this unit, they become visible again.
    """
    def __init__(self, *slice, visible: arg.switch('-n', '--not', off=True, help=(
        'Hide the given chunks instead of making them the only ones visible.')) = True
    ):
        super().__init__(*slice, visible=visible)
        # Sort any slices with negative arguments to the back so we check
        # them last. This delays potential consumption of the chunks iterator
        # as much as possible.
        self.args.slice.sort(
            key=lambda s: (s.start or 0, s.stop or 0), reverse=True)

    def filter(self, chunks):
        it = iter(chunks)
        consumed = None
        size = None

        def buffered():
            yield from it
            while consumed:
                yield consumed.popleft()

        def shift(offset, default):
            nonlocal consumed, it, size
            if offset is None:
                return default
            if offset >= 0:
                return offset
            if consumed is None:
                from collections import deque
                self.log_info(F'consuming iterator to compute negative offset {offset}.')
                consumed = deque(it)
                size = len(consumed) + k + 1
            return max(0, offset + size)

        for k, chunk in enumerate(buffered()):
            for s in self.args.slice:
                if k in range(shift(s.start, 0), shift(s.stop, k + 1), s.step or 1):
                    chunk.visible = self.args.visible
                    break
            else:
                chunk.visible = not self.args.visible
            self.log_debug(chunk)
            yield chunk
