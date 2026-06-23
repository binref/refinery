from __future__ import annotations

from refinery.lib.patterns import wallets
from refinery.lib.wallets import validate
from refinery.units import RefineryCriticalException
from refinery.units.pattern import PatternExtractor, RefinedMatch


class xtw(PatternExtractor):
    """
    Extract Wallets: Extracts anything that looks like a cryptocurrency wallet address.

    The units works similar to `refinery.xtp`. Each candidate is verified against the checksum of
    its address format and discarded when the check fails.
    """

    def __init__(self, stripspace=False, duplicates=False, longest=False, take=0):
        self.superinit(super(), **vars(), ascii=True, utf16=True)

    def process(self, data):
        pattern = '|'.join(FR'(?P<{p.name}>\b{p.value}\b)' for p in wallets)
        pattern = FR'\b{pattern}\b'.encode('latin1')

        def check(match: RefinedMatch):
            for name, value in match.groupdict().items():
                if value is not None:
                    break
            else:
                raise RefineryCriticalException('Received empty match.')
            if not validate(name, value):
                return None
            return self.labelled(value, kind=name)

        yield from self.matches_filtered(memoryview(data), pattern, check)
