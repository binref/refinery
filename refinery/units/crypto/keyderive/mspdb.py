from __future__ import annotations

from refinery.units.crypto.keyderive import KeyDerivation


class mspdb(KeyDerivation):
    """
    An implementation of the PasswordDeriveBytes routine available from the .NET standard library.

    According to documentation, it is an extension of PBKDF1.
    """
    def __init__(self, size, salt, iter=100, hash='SHA1'):
        self.superinit(super(), **vars())

    def keystream(self, seed):
        if not isinstance(seed, bytearray):
            seed = bytearray(seed)
        seed.extend(self.args.salt)
        hf = self._hash_interface()
        for _ in range(self.args.iter - 1):
            seed = hf.new(seed).digest()
        counter, seedhash = 1, seed
        seed = hf.new(seed).digest()
        while len(seed) < self.args.size:
            seed += hf.new(B'%d%s' % (counter, seedhash)).digest()
            counter += 1
        return seed
