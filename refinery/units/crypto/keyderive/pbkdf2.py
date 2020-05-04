#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Crypto.Protocol.KDF import PBKDF2 as PBKDF2_

from . import KeyDerivation


class PBKDF2(KeyDerivation):
    """PBKDF2 Key derivation"""

    def __init__(self, size, salt, iter=1000, hash='SHA1'):
        self.superinit(super(), **vars())

    def process(self, data):
        return PBKDF2_(
            data.decode(self.codec),
            self.args.salt,
            dkLen=self.args.size,
            hmac_hash_module=self.hash,
            count=self.args.iter
        )
