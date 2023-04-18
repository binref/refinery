#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from functools import partial
from refinery.lib.types import ByteStr
from refinery.units.crypto.keyderive import KeyDerivation, multidecode


class pbkdf2(KeyDerivation):
    """
    PBKDF2 Key derivation. This is implemented as Rfc2898DeriveBytes in .NET
    binaries.
    """

    def __init__(self, size, salt, iter=1000, hash='SHA1'):
        self.superinit(super(), **vars())

    def process(self, data: ByteStr):
        from Cryptodome.Protocol.KDF import PBKDF2
        return multidecode(data, partial(
            PBKDF2,
            salt=self.args.salt,
            dkLen=self.args.size,
            hmac_hash_module=self.hash,
            count=self.args.iter
        ))
