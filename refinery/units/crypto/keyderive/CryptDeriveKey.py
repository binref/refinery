#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Reference:
https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptderivekey
"""
from ... import RefineryPartialResult
from . import KeyDerivation, HASH


class CryptDeriveKey(KeyDerivation):
    """
    An implementation of the CryptDeriveKey routine available from the Win32 API.
    """

    def __init__(self, size, hash='MD5'):
        if size > 21:
            raise ValueError('The CryptDeriveKey specification only provides keys up to length 21.')
        super().__init__(size=size, salt=None, hash=hash)

    def process(self, data):
        def digest(x):
            return self.hash.new(x).digest()
        if self.args.hash in (HASH.SHA224, HASH.SHA256, HASH.SHA384, HASH.SHA512):
            return digest(data)[:self.args.size]
        max_size = 2 * self.hash.digest_size
        value = digest(data)
        del data
        buffer1 = bytearray([0x36] * 64)
        buffer2 = bytearray([0x5C] * 64)
        for k, b in enumerate(value):
            buffer1[k] ^= b
            buffer2[k] ^= b
        buffer = digest(buffer1) + digest(buffer2)
        if self.args.size > max_size:
            raise RefineryPartialResult(
                F'too many bytes requested, can only provide {max_size}',
                partial=buffer
            )
        return buffer[:self.args.size]
