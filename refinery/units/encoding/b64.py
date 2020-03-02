#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64

from .. import arg, Unit


class b64(Unit):
    """
    Base64 encoding and decoding.
    """
    def __init__(self, urlsafe: arg.switch('-u', help='use URL-safe alphabet') = False):
        super().__init__(urlsafe=urlsafe)

    @property
    def altchars(self):
        if self.args.urlsafe:
            return B'-_'

    def reverse(self, data):
        return base64.b64encode(data, altchars=self.altchars)

    def process(self, data):
        if len(data) <= 1:
            raise ValueError('single byte can not be base64-decoded.')
        if data:
            data += B'=' * (-len(data) % 4)
            return base64.b64decode(data, altchars=self.altchars)
