#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Crypto.Cipher import AES

from . import StandardCipherUnit


class aes(StandardCipherUnit, cipher=AES):
    """
    AES encryption and decryption.
    """
    pass
