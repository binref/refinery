#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from re import IGNORECASE, escape, compile as regex
from fnmatch import fnmatch

from . import PatternExtractor
from ...lib.patterns import indicators


def on_host(domain):
    return regex(BR'(?:\w{2,8}://)?(?:[\w\-]{1,200}\.)*' + escape(domain) + BR'(?!\.).*')


class xtp(PatternExtractor):
    """
    Extract Patterns: Uses regular expressions to extract indicators from the
    input data. The unit is designed to extract indicators such as domain names
    and IP addresses, see below for a complete list. To extract data formats
    such as hex-encoded data, use `refinery.carve`.
    """

    _WHITELIST = [
        regex(BR'WScript\.Shell', IGNORECASE),
        regex(BR'System\.Net'),
        on_host(B'adobe.com'),
        on_host(B'digicert.com'),
        on_host(B'google.com'),
        on_host(B'microsoft.com'),
        on_host(B'openssl.org'),
        on_host(B'openxmlformats.org'),
        on_host(B'symantec.com'),
        on_host(B'symauth.com'),
        on_host(B'symcb.com'),
        on_host(B'thawte.com'),
        on_host(B'verisign.com'),
        on_host(B'w3.org'),
        on_host(B'xmlsoap.org'),
    ]

    def interface(self, argp):
        argp.add_argument(
            '-i', '--no-whitelist',
            dest='whitelist',
            action='store_false',
            help='Ignore the builtin whitelist.'
        )
        argp.add_argument(
            'pattern',
            metavar='PATTERN',
            type=str,
            nargs='*',
            default=['socket', 'url', 'email'],
            help=(
                'Choose the pattern to extract, defaults are socket, url, and email. '
                'Use an asterix character to select all available patterns. The available '
                'patterns are: {}'.format(', '.join(p.name for p in indicators))
            )
        )
        return super().interface(argp)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.args.pattern = [
            i.value
            for p in self.args.pattern
            for i in indicators
            if fnmatch(i.name, p)
        ]
        self.pattern = '|'.join(F'(?:{p})' for p in self.args.pattern)
        self.log_debug(F'using pattern: {self.pattern}')
        self.pattern = regex(self.pattern.encode('ascii'))

    @classmethod
    def _not_on_whitelist(cls, match):
        _, data = match
        return not any(r.match(data) for r in cls._WHITELIST)

    def process(self, data):
        results = self.matches_filtered(data, self.pattern)
        if self.args.whitelist:
            self.log_info('filtering according to whitelist')
            results = filter(self._not_on_whitelist, results)
        yield from self.matches_finalize(results)
