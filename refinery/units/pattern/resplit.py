#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units.pattern import RegexUnit


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
        view = memoryview(data)
        cursor = 0
        count = self.args.count
        for k, match in enumerate(self.regex.finditer(view), 2):
            yield view[cursor:match.start()]
            cursor = match.end()
            yield from match.groups()
            if k > count > 0:
                break
        yield view[cursor:]
