#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Implements various hashing algorithms.
"""
from ... import Unit


class HashUnit(Unit, abstract=True):

    _algorithm = NotImplemented

    def interface(self, argp):
        argp.add_argument('-t', '--text', action='store_true',
            help='Output a hexadecimal representation of the hash')
        return super().interface(argp)

    def process(self, data: bytes) -> bytes:
        digest = self._algorithm(data)
        return digest.hex().encode(self.codec) if self.args.text else digest
