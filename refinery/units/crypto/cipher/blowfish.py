from __future__ import annotations

from Cryptodome.Cipher import Blowfish

from refinery.units.crypto.cipher import StandardBlockCipherUnit
from refinery.lib.crypto import PyCryptoFactoryWrapper


class blowfish(StandardBlockCipherUnit, cipher=PyCryptoFactoryWrapper(Blowfish)):
    """
    Blowfish encryption and decryption.
    """
    pass
