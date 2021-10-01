#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import KeyDerivation


class HKDF(KeyDerivation):
    """HKDF Key derivation"""

    def __init__(self, size, salt, hash='SHA512'):
        super().__init__(size=size, salt=salt, hash=hash)

    def process(self, data):
        from Crypto.Protocol.KDF import HKDF
        return HKDF(data, self.args.size, self.args.salt, self.hash)
