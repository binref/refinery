#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from struct import unpack

from refinery.units import Unit


class carve_zip(Unit):
    """
    Extracts anything from the input data that looks like a zip archive file.
    """

    def process(self, data):
        cursor = 0
        while True:
            start = data.find(B'PK', cursor)
            if start < cursor:
                break
            end = data.find(B'PK\x05\x06', start + 4)
            if end < 0:
                return None
            size, offset = unpack('<LL', data[end + 12 : end + 20])
            if offset + start + size != end:
                cursor = start + 2
                continue
            end += 22
            yield data[start:end]
            cursor = end
