#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Crypto.Cipher import CAST

from . import StandardBlockCipherUnit


class cast(StandardBlockCipherUnit, cipher=CAST):
    """
    CAST encryption and decryption.
    """
    pass
