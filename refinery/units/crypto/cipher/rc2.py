#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Crypto.Cipher import ARC2

from . import StandardCipherUnit


class rc2(StandardCipherUnit, cipher=ARC2):
    """
    RC2 encryption and decryption.
    """
    pass
