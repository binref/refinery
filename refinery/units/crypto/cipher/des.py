#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Crypto.Cipher import DES

from . import StandardCipherUnit


class des(StandardCipherUnit):
    """
    DES encryption and decryption.
    """
    _cipher = DES
    _requires_iv = True
