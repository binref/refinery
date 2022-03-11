#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units.crypto.hash import HashUnit
from refinery.lib.thirdparty.xxhash import xxhash


class xxh(HashUnit):
    """
    Implements the xxHash hashing algorithm.
    """
    def _algorithm(self, data):
        return xxhash(data)
