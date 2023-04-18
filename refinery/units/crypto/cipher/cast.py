#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Cryptodome.Cipher import CAST

from refinery.units.crypto.cipher import StandardBlockCipherUnit
from refinery.lib.crypto import PyCryptoFactoryWrapper


class cast(StandardBlockCipherUnit, cipher=PyCryptoFactoryWrapper(CAST)):
    """
    CAST encryption and decryption.
    """
    pass
