#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import arg, Unit


class repl(Unit):
    """
    Performs a simple binary string replacement on the input data.
    """

    def __init__(
        self,
        search : arg(help='This is the search term.'),
        replace: arg(help='The substitution string. Leave this empty to remove all occurrences of the search term.') = B'',
        count  : arg.number('-n', help='Only replace the given number of occurrences') = -1
    ):
        super().__init__(search=search, replace=replace, count=count)

    def process(self, data: bytes):
        return data.replace(
            self.args.search,
            self.args.replace,
            self.args.count
        )
