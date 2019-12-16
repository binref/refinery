#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import Unit
from ...lib.argformats import multibin, number


class repl(Unit):
    """
    Performs a simple binary string replacement on the input data.
    """

    def interface(self, argp):
        argp.add_argument('-n', '--count', type=number, default=-1,
            help='Only replace the given number of occurrences')
        argp.add_argument('search', type=multibin,
            help='This is the search term.')
        argp.add_argument('replace', type=multibin, nargs='?', default=B'',
            help='The substitution string. Leave this empty to remove all occurrences of the search term.')
        return super().interface(argp)

    def process(self, data: bytes):
        return data.replace(
            self.args.search,
            self.args.replace,
            self.args.count
        )
