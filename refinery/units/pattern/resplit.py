#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import RegexUnit


class resplit(RegexUnit):
    """
    Splits the data at the given regular expression and returns the sequence of
    chunks between the separators. By default, the input is split along line breaks.
    """

    def __init__(
        self, regex=RB'\r?\n', multiline=False, ignorecase=False, count=0
    ):
        super().__init__(regex=regex, multiline=multiline, ignorecase=ignorecase, count=count)

    def process(self, data):
        split = self.regex.split
        if self.args.count:
            from functools import partial
            split = partial(split, maxsplit=self.args.count)
        yield from split(data)
