from __future__ import annotations

from Cryptodome.Cipher import DES

from refinery.units.crypto.cipher import StandardBlockCipherUnit
from refinery.lib.crypto import PyCryptoFactoryWrapper


class des(StandardBlockCipherUnit, cipher=PyCryptoFactoryWrapper(DES)):
    """
    DES encryption and decryption.
    """
    pass
