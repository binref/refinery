#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Crypto.Protocol.KDF import PBKDF1 as PBKDF1_

from . import KeyDerivation


class PBKDF1(KeyDerivation):
    """PBKDF1 Key derivation"""

    _DEFAULT_ITER = None
    _DEFAULT_HASH = None
    _DEFAULT_SALT = bytes(8)

    def process(self, data):
        kwargs = dict(
            dkLen=self.args.size,
            count=self.iterations,
            hashAlgo=self.algorithm
        )
        kwargs = {k: v for k, v in kwargs.items() if v is not None}
        return PBKDF1_(data.decode(self.codec), self.salt, **kwargs)
