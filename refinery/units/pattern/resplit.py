#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from . import RegexUnit


class resplit(RegexUnit):
    """
    Splits the data at the given regular expression and returns the sequence of
    chunks between the separators. By default, the input is split along line breaks.
    """
    def interface(self, argp):
        return super().interface(argp, regex_default=RB'\r?\n')

    def process(self, data):
        yield from re.split(self.args.regex, data)
