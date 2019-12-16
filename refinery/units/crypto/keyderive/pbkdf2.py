#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Crypto.Protocol.KDF import PBKDF2 as PBKDF2_

from . import KeyDerivation


class PBKDF2(KeyDerivation):
    """PBKDF2 Key derivation"""

    _DEFAULT_ITER = None
    _DEFAULT_SALT = None
    _DEFAULT_HASH = None

    def process(self, data):
        kwargs = dict(
            dkLen=self.args.size,
            count=self.args.iterations,
            hmac_hash_module=self.algorithm
        )
        kwargs = {k: v for k, v in kwargs.items() if v is not None}
        data = PBKDF2_(data.decode(self.codec), self.salt, **kwargs)
        return bytes(data)
