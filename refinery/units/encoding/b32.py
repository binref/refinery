#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64

from refinery.units import Unit


class b32(Unit):
    """
    Base32 encoding and decoding.
    """
    def reverse(self, data):
        return base64.b32encode(data)

    def process(self, data: bytearray):
        before_padding = 0
        for before_padding in range(len(data), 0, -1):
            if data[before_padding - 1:before_padding] != B'=':
                break
        padding_size = -before_padding % 8
        missing = before_padding + padding_size - len(data)
        if missing > 0:
            self.log_info(F'detected incorrect padding: added {missing} padding characters')
            data.extend(B'=' * missing)
        if missing < 0:
            self.log_info(F'detected incorrect padding: removed {-missing} padding characters')
            data[padding_size + before_padding:] = []
        return base64.b32decode(data, casefold=True)
