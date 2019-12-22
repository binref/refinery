#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Crypto.Cipher import Salsa20

from . import LatinStreamCipher


class salsa(LatinStreamCipher, cipher=Salsa20):
    """
    Salsa20 encryption and decryption. The default IV (nonce) value is the
    string value `REFINERY`.
    """
    pass
