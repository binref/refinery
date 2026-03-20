from __future__ import annotations

from Cryptodome.Cipher import Blowfish

from refinery.lib.crypto import PyCryptoFactoryWrapper
from refinery.units.crypto.cipher import StandardBlockCipherUnit


class blowfish(StandardBlockCipherUnit, cipher=PyCryptoFactoryWrapper(Blowfish)):
    """
    Blowfish encryption and decryption.

    A symmetric block cipher with a 64-bit block size and variable key length up to 448 bits,
    designed by Bruce Schneier.
    """
