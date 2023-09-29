#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from refinery.units import Arg, Unit


class trim(Unit):
    """
    Removes byte sequences at beginning and end of input data.
    """

    def __init__(
        self, *junk: Arg(help='Binary strings to be removed, default are all whitespace characters.'),
        unpad: Arg.Switch('-u', help='Also trim partial occurrences of the junk string.') = False,
        left: Arg.Switch('-r', '--right-only', group='SIDE', help='Do not trim left.') = True,
        right: Arg.Switch('-l', '--left-only', group='SIDE', help='Do not trim right.') = True,
    ):
        super().__init__(junk=junk, left=left, right=right, unpad=unpad)

    def process(self, data: bytearray):
        junks = self.args.junk

        if not junks:
            pattern = B'\\s*'
        else:
            pattern = B'|'.join(re.escape(junk) for junk in junks)
            pattern = B'(%s)*' % pattern
            if self.args.unpad:
                partial = B'|'.join(
                    B''.join(B'\\x%02X?' % byte for byte in junk) for junk in junks)
                pattern = B'%s(%s)' % (pattern, partial)

        def left_and_right():
            if self.args.left:
                yield B'(^%s)' % pattern
            if self.args.right:
                yield B'(%s$)' % pattern

        pattern = B'|'.join(p for p in left_and_right())
        return re.sub(pattern, B'', data)
