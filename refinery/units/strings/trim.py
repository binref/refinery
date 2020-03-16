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

    def process(self, data: bytearray):
        keep_running = True
        unview = False
        triml, trimr = self.args.left, self.args.right
        mv = memoryview(data)

        strip = bytes(j[0] for j in self.args.junk if len(j) == 1)

        junkbig = [j for j in self.args.junk if len(j) >= 2]
        escaped = [re.escape(j) for j in junkbig]

        if triml:
            jpl = tuple(re.compile(B'^(?:%s)+' % j) for j in escaped)
        if trimr:
            jpr = tuple(re.compile(B'(?:%s)+$' % j) for j in escaped)

        while keep_running:
            keep_running = False

            if strip:
                if triml and trimr and (mv[0] in strip or mv[-1] in strip):
                    keep_running = True
                    data = data.strip(strip)
                elif triml and mv[0] in strip:
                    keep_running = True
                    data = data.lstrip(strip)
                elif trimr and mv[-1] in strip:
                    keep_running = True
                    data = data.rstrip(strip)
                if keep_running:
                    mv = memoryview(data)
                    unview = False

            for k, junk in enumerate(junkbig):
                jl = len(junk)
                if triml and mv[:jl] == junk:
                    mv = mv[jpl[k].search(mv).end():]
                    unview = True
                    keep_running = True
                if trimr and mv[-jl:] == junk:
                    mv = mv[:jpr[k].search(mv).start()]
                    unview = True
                    keep_running = True

        if unview:
            return bytearray(mv)

        return data
