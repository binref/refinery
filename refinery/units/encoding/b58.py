#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units.encoding.base import base


class b58(base):
    """
    Base58 encoding and decoding. It is famously used as an encoding in Bitcoin addresses
    because the alphabet omits digits and letters that look similar.
    """
    def __init__(self):
        super().__init__(b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz')
