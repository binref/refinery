from __future__ import annotations

from Cryptodome.Cipher import DES3

from refinery.lib.crypto import PyCryptoFactoryWrapper
from refinery.units.crypto.cipher import StandardBlockCipherUnit


class des3(StandardBlockCipherUnit, cipher=PyCryptoFactoryWrapper(DES3)):
    """
    3-DES encryption and decryption.
    """
