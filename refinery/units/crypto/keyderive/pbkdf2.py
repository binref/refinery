from __future__ import annotations

from itertools import count
from typing import Iterable

from refinery.units.crypto.keyderive import KeyDerivation


class pbkdf2(KeyDerivation):
    """
    PBKDF2 Key derivation. This is implemented as Rfc2898DeriveBytes in .NET binaries.
    """

    def __init__(self, size, salt, iter=1000, hash='SHA1'):
        self.superinit(super(), **vars())

    def keystream(self, seed) -> Iterable[int]:
        from Cryptodome.Hash import HMAC
        from Cryptodome.Util.strxor import strxor
        key = self.args.salt
        rounds = self.args.iter
        hash_algorithm = self._hash_module()
        for block in count(1):
            u = HMAC.new(seed, key + block.to_bytes(4, 'big'), hash_algorithm)
            t = bytes(d := u.digest())
            for _ in range(rounds - 1):
                u = HMAC.new(seed, d, hash_algorithm)
                d = u.digest()
                t = strxor(t, d)
            yield from t
