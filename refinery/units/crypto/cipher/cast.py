#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Crypto.Cipher import CAST

from . import StandardCipherUnit


class cast(StandardCipherUnit, cipher=CAST):
    """
    CAST encryption and decryption.
    """
    pass
