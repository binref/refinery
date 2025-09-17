from __future__ import annotations

from refinery.units.meta import ConditionalUnit
from refinery.units.pattern import SingleRegexUnit


class iffx(SingleRegexUnit, ConditionalUnit, docs='{0}{p}{1}'):
    """
    Filter incoming chunks by discarding those that do not match the given
    regular expression.
    """
    def match(self, chunk):
        if matcher := self._make_matcher(self.args.regex):
            return bool(matcher(chunk))
        else:
            return True
