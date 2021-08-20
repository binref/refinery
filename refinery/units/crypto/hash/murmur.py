#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib.murmur import mmh128digest32, mmh128digest64, mmh32digest
from refinery.units.crypto.hash import HashUnit, arg


class MurMurHash(HashUnit, abstract=True):
    def __init__(self, seed: arg.number(help='optional seed value') = 0, text=False):
        super().__init__(seed=seed, text=text)


class mmh32(MurMurHash):
    """
    Returns the 32bit Murmur Hashof the input data.
    """
    def _algorithm(self, data: bytes) -> bytes:
        return mmh32digest(data, self.args.seed)


class mmh128x64(MurMurHash):
    """
    Returns the 128bit Murmur Hash of the input data, 64bit variant.
    """
    def _algorithm(self, data: bytes) -> bytes:
        return mmh128digest64(data, self.args.seed)


class mmh128x32(MurMurHash):
    """
    Returns the 128bit Murmur Hash of the input data, 64bit variant.
    """
    def _algorithm(self, data: bytes) -> bytes:
        return mmh128digest32(data, self.args.seed)
