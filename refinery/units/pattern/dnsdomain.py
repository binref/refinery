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
        def prefilter(matches):
            for match in matches:
                if not isinstance(match, bytearray):
                    match = bytearray(match)
                pos = 0
                while pos < len(match):
                    length = match[pos]
                    match[pos] = 0x2E
                    if len(match) < length + pos:
                        break
                    if any(x not in self._DOMAIN_CHARACTERS for x in match[pos + 1 : pos + length]):
                        break
                    pos += 1 + length
                else:
                    yield bytes(match[1:])
        yield from self.matches_finalize(
            prefilter(self.matches_filtered(memoryview(data), self._DOMAIN_PATTERN)))
