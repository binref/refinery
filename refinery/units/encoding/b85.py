#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import base64
import re

from refinery.units import Unit


class b85(Unit):
    """
    Base85 encoding and decoding.
    """
    def reverse(self, data):
        return base64.b85encode(data)

    def process(self, data):
        if re.search(BR'\s', data) is not None:
            data = re.sub(BR'\s+', B'', data)
        return base64.b85decode(data)

    @classmethod
    def handles(cls, data: bytearray):
        from refinery.lib.patterns import formats
        return formats.spaced_b85.value.bin.fullmatch(data) is not None
