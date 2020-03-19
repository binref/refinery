#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Crypto.Cipher import Blowfish

from . import StandardBlockCipherUnit


class blowfish(StandardBlockCipherUnit, cipher=Blowfish):
    """
    Blowfish encryption and decryption.
    """
    pass
