#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib.patterns import formats, indicators, pattern

from refinery.units.meta import Arg, ConditionalUnit

_PATTERNS = {}
_PATTERNS.update({p.name: p.value for p in formats})
_PATTERNS.update({p.name: p.value for p in indicators})


class iffp(ConditionalUnit, extend_docs=True):
    """
    Filter incoming chunks depending on whether it matches any of a given set of patterns. The
    available patterns are the following: {}.
    """

    def __init__(
        self,
        *patterns: Arg.Choice(metavar='pattern', choices=_PATTERNS),
        partial: Arg.Switch('-p', help='Allow partial matches on the data.') = False,
        negate=False, single=False
    ):
        super().__init__(
            negate=negate,
            single=single,
            patterns=patterns,
            partial=partial
        )

    def match(self, chunk):
        for name in self.args.patterns:
            p: pattern = _PATTERNS[name]
            matcher = p.match if self.args.partial else p.fullmatch
            if matcher(chunk):
                return True
        return False


iffp.__doc__ = iffp.__doc__.format(", ".join(_PATTERNS))
