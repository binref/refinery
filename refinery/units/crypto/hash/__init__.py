#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Implements various hashing algorithms.
"""
from ... import arg, Unit


class HashUnit(Unit, abstract=True):

    _algorithm = NotImplemented

    def __init__(self, text: arg('-t', help='Output a hexadecimal representation of the hash.') = False):
        super().__init__(text=text)

    def process(self, data: bytes) -> bytes:
        digest = self._algorithm(data)
        try: digest = digest.digest()
        except AttributeError: pass
        if self.args.text:
            digest = digest.hex().encode(self.codec)
        return digest
