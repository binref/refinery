#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import re

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
        pattern = '|'.join(FR'(?P<{p.name}>\b{p.value}\b)' for p in wallets)
        pattern = FR'\b{pattern}\b'.encode('latin1')

        def check(match: re.Match[bytes]):
            for name, value in match.groupdict().items():
                if value is not None:
                    break
            else:
                raise RefineryCriticalException('Received empty match.')
            return self.labelled(value, kind=name)

        yield from self.matches_filtered(memoryview(data), pattern, check)
