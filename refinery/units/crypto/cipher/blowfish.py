from __future__ import annotations

from Cryptodome.Cipher import Blowfish

from refinery.lib.crypto import PyCryptoFactoryWrapper
from refinery.units.crypto.cipher import StandardBlockCipherUnit


class blowfish(StandardBlockCipherUnit, cipher=PyCryptoFactoryWrapper(Blowfish)):
    """
    Blowfish encryption and decryption.
    """
