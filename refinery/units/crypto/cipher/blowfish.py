#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Crypto.Cipher import Blowfish

from . import StandardCipherUnit


class blowfish(StandardCipherUnit):
    """
    Blowfish encryption and decryption.
    """
    _cipher = Blowfish
    _requires_iv = True
