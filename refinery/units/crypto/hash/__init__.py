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
        digest = self._algorithm(data).digest()
        return digest.hex().encode(self.codec) if self.args.text else digest
