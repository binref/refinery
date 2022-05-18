#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib.patterns import formats, indicators, pattern

from refinery.units.meta import Arg, ConditionalUnit

_PATTERNS = {}
_PATTERNS.update({p.name: p.value for p in formats})
_PATTERNS.update({p.name: p.value for p in indicators})


class iffp(ConditionalUnit):
    """
    Filter incoming chunks depending on whether it matches any of a given set of patterns. The available
    patterns are the following: {}.
    """

    def __init__(self, *patterns: Arg.Choice(metavar='pattern', choices=_PATTERNS), negate=False, temporary=False):
        super().__init__(negate=negate, temporary=temporary, patterns=patterns)

    def match(self, chunk):
        for name in self.args.patterns:
            p: pattern = _PATTERNS[name]
            if p.fullmatch(chunk):
                return True
        return False


iffp.__doc__ = iffp.__doc__.format(", ".join(_PATTERNS))
