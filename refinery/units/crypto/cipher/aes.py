from __future__ import annotations

from Cryptodome.Cipher import AES

from refinery.lib.crypto import PyCryptoFactoryWrapper
from refinery.units.crypto.cipher import StandardBlockCipherUnit


class aes(StandardBlockCipherUnit, cipher=PyCryptoFactoryWrapper(AES)):
    """
    AES encryption and decryption.
    """
