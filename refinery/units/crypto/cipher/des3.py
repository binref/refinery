#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Crypto.Cipher import DES3

from . import StandardCipherUnit


class des3(StandardCipherUnit):
    """
    3-DES encryption and decryption.
    """
    _cipher = DES3
    _requires_iv = True
