#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units.encoding.base import base


class b62(base):
    """
    Base62 encoding and decoding.
    """
    def __init__(self):
        super().__init__(b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz')

    @classmethod
    def handles(cls, data):
        from refinery.lib.patterns import formats
        return (
            formats.b62.value.fullmatch(data)
            and not formats.hex.value.fullmatch(data)
            and not formats.b32.value.fullmatch(data)
        )
