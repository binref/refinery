from __future__ import annotations

from refinery.units.pattern import SingleRegexUnit
from refinery.units.meta import ConditionalUnit


class iffx(SingleRegexUnit, ConditionalUnit, docs='{0}{p}{1}'):
    """
    Filter incoming chunks by discarding those that do not match the given
    regular expression.
    """
    def match(self, chunk):
        return bool(self.matcher(chunk))
