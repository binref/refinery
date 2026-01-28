from __future__ import annotations

from refinery.lib.types import Param, buf
from refinery.units.meta import Arg, ConditionalUnit


class iffs(ConditionalUnit, docs='{0}{p}{1}'):
    """
    Filter incoming chunks depending on whether they contain a given binary substring.
    """
    def __init__(
        self,
        needle: Param[buf, Arg.Binary(help='The string to search for.')],
        nocase: Param[bool, Arg.Switch('-i', help='Specify to make the search case-insensitive.')],
        retain=False,
    ):
        super().__init__(
            needle=needle,
            nocase=nocase,
            retain=retain,
        )

    def match(self, chunk):
        needle = self.args.needle
        if self.args.nocase:
            from re import IGNORECASE, escape, search
            return search(
                escape(needle), chunk, flags=IGNORECASE
            ) is not None
        else:
            return needle in chunk
