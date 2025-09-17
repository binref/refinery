from __future__ import annotations

from Cryptodome.Cipher import DES

from refinery.lib.crypto import PyCryptoFactoryWrapper
from refinery.units.crypto.cipher import StandardBlockCipherUnit


class des(StandardBlockCipherUnit, cipher=PyCryptoFactoryWrapper(DES)):
    """
    DES encryption and decryption.
    """
