#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Crypto.Cipher import Salsa20

from . import StandardCipherUnit, NonceToIV


class salsa(StandardCipherUnit):
    """
    Salsa20 encryption and decryption. The default IV (nonce) value is the
    string value `REFINERY`.
    """
    _cipher = NonceToIV(Salsa20)
    _requires_iv = False
    _possible_key_sizes = (16, 32)
