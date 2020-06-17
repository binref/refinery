#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import PatternExtractorBase


def _lps(maxlen):
    """
    Brute force regular expression pattern for a length prefixed domain name component.
    """
    return BR'|'.join(BR'\x%02x[a-z0-9\-\_]{%d}' % (d, d) for d in range(1, maxlen + 1))


class dnsdomain(PatternExtractorBase):
    """
    Extracts domain names in the format as they appear in DNS requests. This
    can be used as a quick and dirty way to extract domains from PCAP files,
    for example.
    """

    _DOMAIN_CHARACTERS = (
        B'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        B'abcdefghijklmnopqrstuvwxyz'
        B'0123456789-_'
    )

    _DOMAIN_PATTERN = BR'(?:%s){1,20}(?:%s)\b' % (_lps(0xFF), _lps(25))

    def process(self, data):

        def transform(match):
            match = bytearray(match[0])
            pos = 0
            while pos < len(match):
                length = match[pos]
                match[pos] = 0x2E
                if len(match) < length + pos:
                    return None
                if any(x not in self._DOMAIN_CHARACTERS for x in match[pos + 1 : pos + length]):
                    return None
                pos += 1 + length
            return match[1:]

        yield from self.matches_filtered(memoryview(data), self._DOMAIN_PATTERN, transform)
