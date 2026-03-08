from __future__ import annotations

from refinery.units.crypto.keyderive import KeyDerivation


class hkdf(KeyDerivation):
    """
    HKDF key derivation as specified in RFC 5869. An extract-and-expand key derivation function used
    in TLS 1.3 and many modern protocols.
    """

    def __init__(self, size, salt, hash='SHA512'):
        super().__init__(size=size, salt=salt, hash=hash)

    def process(self, data):
        from Cryptodome.Protocol.KDF import HKDF
        return HKDF(data, self.args.size, self.args.salt, self.hash)
