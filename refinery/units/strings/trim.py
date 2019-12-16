#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from string import whitespace
import re

from .. import Unit
from ...lib.argformats import multibin


class trim(Unit):
    """
    Removes byte sequences at beginning and end of input data.
    """

    def interface(self, argp):
        argp.add_argument('junk', type=multibin,
            default=[w.encode('ascii') for w in whitespace],
            help='Character(s) to be removed, default is whitespace.', nargs='*')
        one_side_only = argp.add_mutually_exclusive_group()
        one_side_only.add_argument('-l', '--left-only', action='store_true')
        one_side_only.add_argument('-r', '--right-only', action='store_true')
        return super().interface(argp)

    def process(self, data):
        keep_running = True
        while keep_running:
            keep_running = False
            for junk in self.args.junk:
                jlen = len(junk)
                if not self.args.right_only:
                    if data.startswith(junk):
                        if jlen == 1:
                            data = data.lstrip(junk)
                        else:
                            pattern = B'^(?:' + B''.join(B'\\x%02X' % X for X in junk) + B')+'
                            match = re.search(pattern, data)
                            data = data[match.end():]
                        keep_running = True
                if not self.args.left_only:
                    if data.endswith(junk):
                        if jlen == 1:
                            data = data.rstrip(junk)
                        else:
                            pattern = B'(?:' + B''.join(B'\\x%02X' % X for X in junk) + B')+$'
                            match = re.search(pattern, data)
                            data = data[:match.start()]
                        keep_running = True
        return data
