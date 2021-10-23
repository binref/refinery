#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Crypto.Cipher import ARC2

from refinery.units.crypto.cipher import StandardBlockCipherUnit


class rc2(StandardBlockCipherUnit, cipher=ARC2):
    """
    RC2 encryption and decryption.
    """
    pass
