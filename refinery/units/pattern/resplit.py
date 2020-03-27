#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from . import RegexUnit


class resplit(RegexUnit):
    """
    Splits the data at the given regular expression and returns the sequence of
    chunks between the separators. By default, the input is split along line breaks.
    """

    def __init__(
        self, regex=RB'\r?\n',
        # TODO: Use positional only in Python 3.8
        # /,
        multiline=False, ignorecase=False, min=1, max=None, len=None, stripspace=False,
        unique=False, longest=False, take=None, utf16=False
    ):
        super().__init__(
            regex,
            min=min,
            max=max,
            len=len,
            stripspace=stripspace,
            unique=unique,
            utf16=utf16,
            longest=longest,
            take=take
        )

    def process(self, data):
        yield from re.split(self.args.regex, data)
