#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Crypto.Cipher import CAST

from . import StandardCipherUnit


class cast(StandardCipherUnit):
    """
    CAST encryption and decryption.
    """
    _cipher = CAST
    _requires_iv = False
