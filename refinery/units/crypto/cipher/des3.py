#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Cryptodome.Cipher import DES3

from refinery.units.crypto.cipher import StandardBlockCipherUnit
from refinery.lib.crypto import PyCryptoFactoryWrapper


class des3(StandardBlockCipherUnit, cipher=PyCryptoFactoryWrapper(DES3)):
    """
    3-DES encryption and decryption.
    """
    pass
