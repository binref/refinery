#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Crypto.Cipher import DES

from . import StandardBlockCipherUnit


class des(StandardBlockCipherUnit, cipher=DES):
    """
    DES encryption and decryption.
    """
    pass
