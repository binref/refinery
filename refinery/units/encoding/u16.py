#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import Unit


class u16(Unit):
    """
    Encodes and decodes UTF-16LE encoded string data.
    """

    def reverse(self, data):
        return data.decode(self.codec).encode('utf-16LE')

    def process(self, data):
        return data.decode('utf-16LE').encode(self.codec)
