from __future__ import annotations

from refinery.lib.patterns import formats, indicators, pattern
from refinery.lib.types import Param
from refinery.units.meta import Arg, ConditionalUnit

_PATTERNS = {
    p.name: p.value for d in (formats, indicators) for p in d
}


class iffp(ConditionalUnit, docs='{0}{p}{1}'):
    """
    Filter incoming chunks depending on whether it matches any of a given set of patterns. The
    available patterns are the following: {}.
    """

    def __init__(
        self,
        *patterns: Param[str, Arg.Choice(metavar='pattern', choices=list(_PATTERNS))],
        partial: Param[bool, Arg.Switch('-p', help='Allow partial matches on the data.')] = False,
        retain=False
    ):
        super().__init__(
            retain=retain,
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


if __doc := iffp.__doc__:
    iffp.__doc__ = __doc.format(", ".join(_PATTERNS))
