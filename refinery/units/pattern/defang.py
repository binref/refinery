#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import Unit
from ...lib.patterns import defanged, indicators


class defang(Unit):
    """
    Defangs all domains and ipv4 addresses in the input data by replacing the
    last dot in the expression by `[.]`. For example, `127.0.0.1` will be
    replaced by `127.0.0[.]1`.
    """

    WHITELIST = [
        B'wscript.shell',
    ]

    @classmethod
    def interface(cls, argp):
        argp.add_argument('-q', '--quote', action='store_true', help='Wrap all indicators in backticks for markdown code.')
        argp.add_argument('-u', '--url-only', action='store_true', help='Only defang URLs, do not look for domains or IPs.')
        argp.add_argument('-d', '--dot-only', dest='protocol', action='store_false', help='Do not escape the protocol colon in URLs.')
        return super().interface(argp)

    def _quote(self, word):
        return word if not self.args.quote else B'`%s`' % word

    def reverse(self, data):
        def refang(hostname):
            return hostname.group(0).replace(B'[.]', B'.')
        data = defanged.hostname.sub(refang, data)
        data = data.replace(B'[:]//', B'://')
        return data

    def process(self, data):
        def replace_hostname(hostname, match=True):
            if match:
                return self._quote(replace_hostname(hostname.group(0), False))
            self.log_info('replace:', hostname)
            host = hostname.rsplit(B':')[0].lower()
            if host in self.WHITELIST:
                return hostname
            return B'[.]'.join(hostname.rsplit(B'.', 1))

        def replace_url(url):
            if not url:
                return url
            sep = B'[:]//' if self.args.protocol else B'://'
            self.log_info('replace:', url)
            p, q = url.split(B'://')
            q = q.split(B'/', 1)
            q[0] = replace_hostname(q[0], False)
            q = B'/'.join(q)
            return self._quote(p + sep + q)

        analyze = indicators.url.split(data)
        analyze[1::2] = [replace_url(t) for t in analyze[1::2]]

        if not self.args.url_only:
            analyze[0::2] = [
                indicators.hostname.sub(replace_hostname, t)
                for t in analyze[0::2]
            ]

        return B''.join(analyze)
