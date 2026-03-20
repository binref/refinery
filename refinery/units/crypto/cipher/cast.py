from __future__ import annotations

from Cryptodome.Cipher import CAST

from refinery.lib.crypto import PyCryptoFactoryWrapper
from refinery.units.crypto.cipher import StandardBlockCipherUnit


class cast(StandardBlockCipherUnit, cipher=PyCryptoFactoryWrapper(CAST)):
    """
    CAST encryption and decryption.

    A symmetric block cipher (CAST-128) with a 64-bit block size, used in PGP and OpenSSL.
    """
