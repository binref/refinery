#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Crypto.Cipher import DES3

from . import StandardCipherUnit


class des3(StandardCipherUnit, cipher=DES3):
    """
    3-DES encryption and decryption.
    """
    pass
