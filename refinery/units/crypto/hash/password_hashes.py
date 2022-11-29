#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Implements password hashing algorithms.
"""
import hashlib

from refinery.units.crypto.hash import HashUnit


class ntlm(HashUnit):
    """
    Returns the Windows NTLM hash of the input.
    """
    def _algorithm(self, data: bytes) -> bytes:
        return hashlib.new('md4', data.decode(self.codec).encode("utf-16le")).digest()
