#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Crypto.Cipher import ARC4

from . import StandardCipherUnit

ARC4.key_size = range(1, 257)


class rc4(StandardCipherUnit, cipher=ARC4):
    """
    RC4 encryption and decryption.
    """
    def __init__(self, key): super().__init__(key)
