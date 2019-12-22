#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Crypto.Cipher import Blowfish

from . import StandardCipherUnit


class blowfish(StandardCipherUnit, cipher=Blowfish):
    """
    Blowfish encryption and decryption.
    """
    pass
