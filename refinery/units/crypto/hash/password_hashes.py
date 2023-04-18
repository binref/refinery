#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Implements password hashing algorithms.
"""
from refinery.units.crypto.hash import HashUnit


class ntlm(HashUnit):
    """
    Returns the Windows NTLM hash of the input.
    """
    def _algorithm(self, data: bytes) -> bytes:
        from Cryptodome.Hash import MD4
        return MD4.new(data.decode(self.codec).encode('utf-16le'))
