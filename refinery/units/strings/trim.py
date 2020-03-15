#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from .. import arg, Unit


class trim(Unit):
    """
    Removes byte sequences at beginning and end of input data.
    """

    def __init__(
        self, *junk: arg.help('Binary strings to be removed, default are all whitespace characters.'),
        left: arg.switch('-r', '--right-only', group='SIDE', help='Do not trim left.') = True,
        right: arg.switch('-l', '--left-only', group='SIDE', help='Do not trim right.') = True
    ):
        if not junk:
            import string
            junk = [w.encode('ascii') for w in string.whitespace]

        super().__init__(junk=junk, left=left, right=right)

    def process(self, data):
        keep_running = True
        mv = memoryview(data)

        if self.args.left:
            jpl = tuple(re.compile(B'^(?:%s)+' % re.escape(j)) for j in self.args.junk)
        if self.args.right:
            jpr = tuple(re.compile(B'(?:%s)+$' % re.escape(j)) for j in self.args.junk)

        while keep_running:
            keep_running = False
            for k, junk in enumerate(self.args.junk):
                jl = len(junk)
                if self.args.left and mv[:jl] == junk:
                    mv = mv[jpl[k].search(mv).end():]
                    keep_running = True
                if self.args.right and mv[-jl:] == junk:
                    mv = mv[:jpr[k].search(mv).start()]
                    keep_running = True

        return bytearray(mv)
