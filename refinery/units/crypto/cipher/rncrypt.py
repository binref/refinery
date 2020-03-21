#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
The source code for this refinery unit is based on RNCryptor for Python:

  https://github.com/RNCryptor/RNCryptor-python

Regardless of what license binary refinery is released under, the current file is
subject to the same MIT license as the original RNCryptor source code:

    MIT License

    Copyright (C) 2013-2016 Rob Napier, Yan Kalchevskiy, Brant Young

    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
    of the Software, and to permit persons to whom the Software is furnished to do
    so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

RNCryptor is Copyright (C) 2013-2016 Rob Napier, Yan Kalchevskiy, Brant Young.
"""
from ... import Unit

import hashlib
import hmac

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Protocol import KDF
from Crypto.Util.Padding import unpad, pad


class rncrypt(Unit):
    """
    Implements encryption and decryption using the RNCryptor specification.
    See also: https://github.com/RNCryptor
    """
    def __init__(self, password: bytearray):
        super().__init__(password=password)

    def process(self, data: bytes) -> bytes:
        encryption_salt = data[2:10]
        hmac_salt = data[10:18]
        iv = data[18:34]
        cipher_text = data[34:-32]
        hmac_signature = data[-32:]
        encryption_key = self._pbkdf2(self.args.password, encryption_salt)
        hmac_key = self._pbkdf2(self.args.password, hmac_salt)
        if not hmac.compare_digest(self._hmac(hmac_key, data[:-32]), hmac_signature):
            raise ValueError("Failed to verify signature.")
        return unpad(
            self._aes_decrypt(encryption_key, iv, cipher_text),
            block_size=AES.block_size
        )

    def reverse(self, data: bytes) -> bytes:
        prng = Random.new()
        data = pad(data, block_size=AES.block_size)
        encryption_salt = prng.read(8)
        encryption_key = self._pbkdf2(self.args.password, encryption_salt)
        hmac_salt = prng.read(8)
        hmac_key = self._pbkdf2(self.args.password, hmac_salt)
        iv = prng.read(AES.block_size)
        cipher_text = self._aes_encrypt(encryption_key, iv, data)
        new_data = b'\x03\x01' + encryption_salt + hmac_salt + iv + cipher_text
        return new_data + self._hmac(hmac_key, new_data)

    def _aes_encrypt(self, key, iv, text):
        return AES.new(key, AES.MODE_CBC, iv).encrypt(text)

    def _aes_decrypt(self, key, iv, text):
        return AES.new(key, AES.MODE_CBC, iv).decrypt(text)

    def _hmac(self, key, data):
        return hmac.new(key, data, hashlib.sha256).digest()

    def _prf(self, secret, salt):
        return hmac.new(secret, salt, hashlib.sha1).digest()

    def _pbkdf2(self, password, salt, iterations=10000, key_length=32):
        return KDF.PBKDF2(password, salt, dkLen=key_length, count=iterations, prf=self._prf)
