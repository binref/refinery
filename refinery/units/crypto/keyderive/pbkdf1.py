#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import arg, KeyDerivation


class PBKDF1(KeyDerivation):
    """PBKDF1 Key derivation"""

    @arg('salt', help='Salt for the derivation; default are 8 null bytes.')
    def __init__(self, size, salt=bytes(8), iter=1000, hash='SHA1'):
        self.superinit(super(), **vars())

    def process(self, data):
        from Crypto.Protocol.KDF import PBKDF1
        return PBKDF1(
            data.decode(self.codec),
            self.args.salt,
            dkLen=self.args.size,
            count=self.args.iter,
            hashAlgo=self.hash
        )
