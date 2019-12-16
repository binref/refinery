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
    def interface(self, argp):
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
        skip = 0
        consumed = False

        while slices:
            s = slices.popleft()
            skipamount = 0
            if not consumed and slices:
                if s.stop and all(t.start >= s.stop for t in slices):
                    skipamount = s.stop - 1 - skip
                    self.log_debug(F'skipping {skipamount} items without consuming')
                else:
                    self.log_debug(F'consumed input into buffer after {skip} skips')
                    inputs = list(inputs)
                    consumed = True
            self.log_debug(F'applying slice {s}')
            yield from islice(chain(repeat(None, skip), inputs), s.start, s.stop, s.step)
            skip += skipamount

        return
