#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Crypto.Cipher import ChaCha20

from . import LatinStreamCipher


class chacha(LatinStreamCipher, cipher=ChaCha20):
    """
    ChaCha20 and XChaCha20 encryption and decryption. For ChaCha20, the IV
    (nonce) must be 8 or 12 bytes long; for XChaCha20, choose an IV which is
    24 bytes long. The default IV value is the string value `REFINERY`.
    """
    pass
