#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units.pattern import PatternExtractor
from refinery.units import RefineryCriticalException
from refinery.lib.patterns import wallets


class xtw(PatternExtractor):
    """
    Extract Wallets: Extracts anything that looks like a cryptocurrency wallet address.
    This works similar to the `refinery.xtp` unit.
    """

    def __init__(self, stripspace=False, duplicates=False, longest=False, take=None):
        self.superinit(super(), **vars(), ascii=True, utf16=True)

    def process(self, data):
        pattern = '|'.join(F'(?P<{p.name}>{p.value})' for p in wallets).encode('latin1')

        def check(match):
            for name, value in match.groupdict().items():
                if value is not None:
                    break
            else:
                raise RefineryCriticalException('Received empty match.')
            return self.labelled(value, kind=name)

        yield from self.matches_filtered(memoryview(data), pattern, check)
