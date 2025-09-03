from __future__ import annotations

from refinery.units.crypto.keyderive import KeyDerivation


class hmac(KeyDerivation):
    """
    HMAC based key derivation
    """

    def __init__(self, salt, hash='SHA1', size=None):
        super().__init__(salt=salt, size=size, hash=hash)

    def process(self, data):
        from Cryptodome.Hash import HMAC
        return HMAC.new(data, self.args.salt, digestmod=self.hash).digest()
