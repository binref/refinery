#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import RefineryPartialResult
from ....lib.crypto import des_set_odd_parity
from . import arg, KeyDerivation

from Crypto.Cipher import DES
from Crypto.Util.strxor import strxor

__all__ = ['DESDerive']


class DESDerive(KeyDerivation):
    """
    Implements the same functionality as `DES_string_to_key` in OpenSSL. It
    converts a string to an 8 byte DES key with odd byte parity, per FIPS
    specification. This is not a modern key derivation function.
    """
    def __init__(self, size: arg(help='The number of bytes to generate, default is the maximum of 8.') = 8):
        super().__init__(size=size, salt=None)

    def process(self, password):
        key = bytearray(8)

        for i, j in enumerate(password):
            if ((i % 16) < 8):
                key[i % 8] ^= (j << 1) & 0xFF
            else:
                j = (((j << 4) & 0xf0) | ((j >> 4) & 0x0f))
                j = (((j << 2) & 0xcc) | ((j >> 2) & 0x33))
                j = (((j << 1) & 0xaa) | ((j >> 1) & 0x55))
                key[7 - (i % 8)] ^= j

        des_set_odd_parity(key)

        if password:
            n = len(password)
            password = password.ljust(n + 7 - ((n - 1) % 8), b'\0')
            des = DES.new(key, DES.MODE_ECB)
            for k in range(0, n, 8):
                key[:] = des.encrypt(strxor(password[k:k + 8], key))
            des_set_odd_parity(key)

        if self.args.size > 8:
            raise RefineryPartialResult('DESDerive can provide at most 8 bytes.', partial=key)

        return key[:self.args.size]
