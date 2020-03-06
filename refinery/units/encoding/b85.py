#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64

from .. import Unit


class b85(Unit):
    """
    Base85 encoding and decoding.
    """
    def reverse(self, data):
        return base64.b85encode(data)

    def process(self, data):
        return base64.b85decode(data)
