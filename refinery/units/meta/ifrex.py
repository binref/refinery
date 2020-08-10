#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ..pattern import arg, RegexUnit


class ifrex(RegexUnit):
    """
    Filter incoming chunks by discarding those that do not match the given
    regular expression.
    """
    def __init__(
        self, regex, multiline=False, ignorecase=False,
        match: arg.switch('-m',
            help='Perform a full match rather than anywhere in the chunk.') = False
    ):
        super().__init__(regex=regex, multiline=multiline, ignorecase=ignorecase, match=match)

    def filter(self, inputs):
        matcher = self.args.regex.fullmatch if self.args.match else self.args.regex.search
        for chunk in inputs:
            if matcher(chunk): yield chunk
