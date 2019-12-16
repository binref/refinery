#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Crypto.Protocol.KDF import HKDF as HKDF_

from . import KeyDerivation


class HKDF(KeyDerivation):
    """HKDF Key derivation"""

    _DEFAULT_SALT = None
    _DEFAULT_HASH = 'SHA512'

    def process(self, data):
        return HKDF_(data, self.args.size, self.salt, self.algorithm)
