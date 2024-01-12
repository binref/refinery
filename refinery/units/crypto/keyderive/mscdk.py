#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Reference:
https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptderivekey
"""
from refinery.units import RefineryPartialResult
from refinery.units.crypto.keyderive import KeyDerivation, HASH


class mscdk(KeyDerivation):
    """
    An implementation of the CryptDeriveKey routine available from the Win32 API.
    """

    def __init__(self, size, hash='MD5'):
        super().__init__(size=size, salt=None, hash=hash)

    def process(self, data):
        def digest(x):
            return self.hash.new(x).digest()
        size = self.args.size
        if self.args.hash in (HASH.SHA224, HASH.SHA256, HASH.SHA384, HASH.SHA512):
            buffer = digest(data)
            max_size = len(buffer)
        else:
            max_size = 2 * self.hash.digest_size
            value = digest(data)
            del data
            buffer1 = bytearray([0x36] * 64)
            buffer2 = bytearray([0x5C] * 64)
            for k, b in enumerate(value):
                buffer1[k] ^= b
                buffer2[k] ^= b
            buffer = digest(buffer1) + digest(buffer2)
        if size > max_size:
            raise RefineryPartialResult(F'too many bytes requested, can only provide {max_size}', partial=buffer)
        return buffer[:size]
