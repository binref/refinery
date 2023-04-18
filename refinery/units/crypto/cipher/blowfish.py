#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Cryptodome.Cipher import Blowfish

from refinery.units.crypto.cipher import StandardBlockCipherUnit
from refinery.lib.crypto import PyCryptoFactoryWrapper


class blowfish(StandardBlockCipherUnit, cipher=PyCryptoFactoryWrapper(Blowfish)):
    """
    Blowfish encryption and decryption.
    """
    pass
