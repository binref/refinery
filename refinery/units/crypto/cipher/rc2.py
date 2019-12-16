#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Crypto.Cipher import ARC2

from . import StandardCipherUnit


class rc2(StandardCipherUnit):
    """
    RC2 encryption and decryption.
    """
    _cipher = ARC2
    _requires_iv = False
