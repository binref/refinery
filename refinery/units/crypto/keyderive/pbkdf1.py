from __future__ import annotations

import codecs

from refinery.units.crypto.keyderive import Arg, KeyDerivation


class pbkdf1(KeyDerivation):
    """
    PBKDF1 key derivation as specified in RFC 2898. A password-based key derivation function using
    iterated hashing, predecessor to PBKDF2.
    """

    @Arg('salt', help='Salt for the derivation; default are 8 null bytes.')
    def __init__(self, size, salt=bytes(8), iter=1000, hash='SHA1'):
        self.superinit(super(), **vars())

    def keystream(self, seed):
        from Cryptodome.Protocol.KDF import PBKDF1
        return PBKDF1(
            codecs.decode(seed, self.codec),
            self.args.salt,
            dkLen=self._hash_interface().digest_size,
            count=self.args.iter,
            hashAlgo=self._hash_module(),
        )
