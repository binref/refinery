from __future__ import annotations

from typing import Iterable

from refinery.units.crypto.keyderive import KeyDerivation


class hkdf(KeyDerivation):
    """
    HKDF key derivation as specified in RFC 5869. An extract-and-expand key derivation function used
    in TLS 1.3 and many modern protocols.
    """

    def __init__(self, size, salt, hash='SHA512'):
        super().__init__(size=size, salt=salt, hash=hash)

    def keystream(self, seed) -> Iterable[int]:
        from Cryptodome.Hash import HMAC
        hash_algorithm = self._hash_module()
        prk = HMAC.new(self.args.salt, seed, hash_algorithm).digest()
        previous = bytearray(1)
        for counter in range(1, 256):
            previous[-1] = counter
            u = HMAC.new(prk, previous, hash_algorithm)
            d = u.digest()
            yield from d
            previous[:-1] = d
