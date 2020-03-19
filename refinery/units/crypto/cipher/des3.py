#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Crypto.Cipher import DES3

from . import StandardBlockCipherUnit


class des3(StandardBlockCipherUnit, cipher=DES3):
    """
    3-DES encryption and decryption.
    """
    pass
