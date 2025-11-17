from __future__ import annotations

from refinery.lib.mscrypto import CRYPTOKEY
from refinery.units import Unit


class kblob(Unit):
    """
    Extracts a key from a Microsoft Crypto API BLOB structure.
    """

    def process(self, data):
        blob = CRYPTOKEY.Parse(data)
        try:
            return self.labelled(
                bytes(blob.key),
                type=blob.header.type.name,
                algorithm=blob.header.algorithm.name
            )
        except AttributeError as A:
            raise ValueError(F'unable to derive key from {blob.header.type!s}') from A
