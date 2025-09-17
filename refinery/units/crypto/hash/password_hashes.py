"""
Implements password hashing algorithms.
"""
from __future__ import annotations

import codecs

from refinery.units.crypto.hash import HashUnit


class ntlm(HashUnit):
    """
    Returns the Windows NTLM hash of the input.
    """
    def _algorithm(self, data) -> bytes:
        from Cryptodome.Hash import MD4
        return MD4.new(codecs.decode(data, self.codec).encode('utf-16le')).digest()
