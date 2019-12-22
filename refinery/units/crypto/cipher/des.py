#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Crypto.Cipher import DES

from . import StandardCipherUnit


class des(StandardCipherUnit, cipher=DES):
    """
    DES encryption and decryption.
    """
    pass
