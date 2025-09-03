from __future__ import annotations

from refinery.units.crypto.keyderive import KeyDerivation


class hkdf(KeyDerivation):
    """HKDF Key derivation"""

    def __init__(self, size, salt, hash='SHA512'):
        super().__init__(size=size, salt=salt, hash=hash)

    def process(self, data):
        from Cryptodome.Protocol.KDF import HKDF
        return HKDF(data, self.args.size, self.args.salt, self.hash)
