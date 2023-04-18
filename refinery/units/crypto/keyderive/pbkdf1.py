#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units.crypto.keyderive import Arg, KeyDerivation, multidecode


class pbkdf1(KeyDerivation):
    """PBKDF1 Key derivation"""

    @Arg('salt', help='Salt for the derivation; default are 8 null bytes.')
    def __init__(self, size, salt=bytes(8), iter=1000, hash='SHA1'):
        self.superinit(super(), **vars())

    def process(self, data):
        from Cryptodome.Protocol.KDF import PBKDF1
        return multidecode(data, lambda pwd: (
            PBKDF1(pwd, self.args.salt, dkLen=self.args.size, count=self.args.iter, hashAlgo=self.hash)
        ))
