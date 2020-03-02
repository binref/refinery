#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import Unit
from ...lib.argformats import sliceobj

from itertools import islice, repeat, chain
from collections import deque


class pick(Unit):
    """
    Picks sequences from the array of multiple inputs. For example, `pick 0 2:`
    will return all but the second ingested input (which has index `1`).
    """
    @classmethod
    def interface(cls, argp):
        argp.add_argument(
            'slice',
            type=sliceobj,
            nargs='*',
            default=[slice(None, None)],
            help='Specify start:stop:step in Python slice syntax.'
        )
        return super().interface(argp)

    def filter(self, inputs):
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
                    inputs = [None] * discards + list(inputs)
                    consumed = True

            if consumed:
                yield from inputs[s]
            else:
                yield from islice(chain(repeat(None, discards), inputs), s.start, s.stop, s.step)
                discards = s.stop

        return
