from __future__ import annotations

from Cryptodome.Cipher import DES

from refinery.lib.crypto import PyCryptoFactoryWrapper
from refinery.units.crypto.cipher import StandardBlockCipherUnit


class des(StandardBlockCipherUnit, cipher=PyCryptoFactoryWrapper(DES)):
    """
    DES encryption and decryption.

    A legacy symmetric block cipher with a 64-bit block size and 56-bit key, now considered
    insecure but still found in older systems.
    """
