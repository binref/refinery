#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64

from .. import Unit


class b32(Unit):
    """
    Base32 encoding and decoding.
    """
    def reverse(self, data):
        return base64.b32encode(data)

    def process(self, data):
        return base64.b32decode(data, casefold=True)
