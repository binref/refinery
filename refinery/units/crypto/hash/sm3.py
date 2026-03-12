from __future__ import annotations

from refinery.units.crypto.hash import HashUnit


class sm3(HashUnit):
    """
    Returns the SM3 hash of the input data. SM3 is a Chinese cryptographic hash function standard
    (GM/T 0004-2012), published by the State Cryptography Administration (SCA) of China. It
    produces a 256-bit (32-byte) digest and is structurally similar to SHA-256 but uses a
    different compression function with 64 rounds. SM3 is mandatory in Chinese commercial
    cryptography applications and is used in the Chinese TLS standard (TLCP), digital signatures,
    and certificate validation. It is part of the SM series of Chinese cryptographic standards
    alongside `refinery.units.crypto.cipher.sm4`.
    """
    def _algorithm(self, data):
        from refinery.lib.crypto.sm3 import sm3_digest
        return sm3_digest(data)
