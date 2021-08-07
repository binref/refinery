#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ...lib.patterns import formats, indicators, pattern

from . import arg, ConditionalUnit

_PATTERNS = {}
_PATTERNS.update({p.name: p.value for p in formats})
_PATTERNS.update({p.name: p.value for p in indicators})


class iffp(ConditionalUnit):
    F"""
    Filter incoming chunks depending on whether it matches any of a given set of patterns. The available
    patterns are the following: {", ".join(_PATTERNS)}.
    """

    def __init__(self, *patterns: arg.choice(metavar='pattern', choices=_PATTERNS), negate=False, temporary=False):
        super().__init__(negate=negate, temporary=temporary, patterns=patterns)

    def match(self, chunk):
        for name in self.args.patterns:
            p: pattern = _PATTERNS[name]
            if p.fullmatch(chunk):
                return True
        return False
