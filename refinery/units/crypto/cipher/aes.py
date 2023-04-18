#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Cryptodome.Cipher import AES

from refinery.units.crypto.cipher import StandardBlockCipherUnit
from refinery.lib.crypto import PyCryptoFactoryWrapper


class aes(StandardBlockCipherUnit, cipher=PyCryptoFactoryWrapper(AES)):
    """
    AES encryption and decryption.
    """
    pass
