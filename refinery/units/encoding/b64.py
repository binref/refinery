#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64

from .. import Unit


class b64(Unit):
    """
    Base64 encoding and decoding.
    """

    def interface(self, argp):
        argp.add_argument(
            '-u', '--urlsafe',
            dest='altchars',
            action='store_const',
            default=None,
            const=B'-_',
            help='use urlsafe special chars -_'
        )
        return super().interface(argp)

    def reverse(self, data):
        return base64.b64encode(data, altchars=self.args.altchars)

    def process(self, data):
        if len(data) <= 1:
            raise ValueError('single byte can not be base64-decoded.')
        if data:
            data += B'=' * (-len(data) % 4)
            return base64.b64decode(data, altchars=self.args.altchars)
