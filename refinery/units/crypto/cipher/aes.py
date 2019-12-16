#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Crypto.Cipher import AES

from . import StandardCipherUnit


class aes(StandardCipherUnit):
    """
    AES encryption and decryption.
    """
    _cipher = AES
    _requires_iv = True
