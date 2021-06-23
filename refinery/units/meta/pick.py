#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import arg, Unit
from ...lib.argformats import sliceobj

from itertools import islice, repeat, chain
from collections import deque


class pick(Unit):
    """
    Picks sequences from the array of multiple inputs. For example, `pick 0 2:`
    will return all but the second ingested input (which has index `1`).
    """
    def __init__(self, *slice: arg(
        type=sliceobj, nargs='*', default=[slice(None, None)],
        help='Specify start:stop:step in Python slice syntax.'
    )):
        super().__init__(slice=slice)

    def filter(self, chunks):
        slices = deque(self.args.slice)
        discards = 0
        consumed = False

        def discardable(s):
            return s.stop and s.stop >= 0 and (s.step or 1) > 0 \
                and all(t.start >= s.stop for t in slices)

        while slices:
            s = slices.popleft()

            if not consumed:
                if not discardable(s):
                    self.log_debug(F'consumed input into buffer after {discards} skips')
                    chunks = [None] * discards + list(chunks)
                    consumed = True

            if consumed:
                yield from chunks[s]
            else:
                yield from islice(chain(repeat(None, discards), chunks), s.start, s.stop, s.step)
                discards = s.stop

        return
