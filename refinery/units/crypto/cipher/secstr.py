#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
from Crypto.Cipher import AES
from Crypto.Random import urandom
from Crypto.Util.Padding import pad, unpad

from ... import arg, Unit


class secstr(Unit):
    """
    Implements the AES-based encryption scheme used by the PowerShell commands
    `ConvertFrom-SecureString` and `ConvertTo-SecureString`.
    """

    # This is a magic header value used for PowerShell secure strings.
    _MAGIC = bytes((
        0xEF, 0xAE, 0x3D, 0xD9, 0xDD, 0x75, 0xD7, 0xAE, 0xF8, 0xDD, 0xFD, 0x38,
        0xDB, 0x7E, 0x35, 0xDD, 0xBD, 0x7A, 0xD3, 0x9D, 0x1A, 0xE7, 0x7E, 0x39))

    # Secure strings include a decimal number formatted as a string directly
    # following the header. Presumably, this is the PowerShell version.
    _PSVER = 2

    def __init__(
        self, key: arg(
            help='Secure string encryption 16-byte AES key; the default are the bytes from 1 to 16.'
        ) = bytes(range(1, 17)),
        iv: arg('-I', help='Optionally specify an IV to use for encryption.') = None
    ):
        super().__init__(key=key, iv=iv)

    @property
    def key(self):
        key = self.args.key
        if len(key) != 0x10:
            raise ValueError('The encryption key has to be 16 bytes long.')
        return key

    @property
    def iv(self):
        iv = self.args.iv
        if iv is not None and len(iv) != 0x10:
            raise ValueError('The IV has to be 16 bytes long.')
        return iv

    def reverse(self, data):
        ivec = self.iv or urandom(0x10)
        if len(ivec) != 0x10:
            raise ValueError(self._IVERR)
        cipher = AES.new(self.key, AES.MODE_CBC, ivec)
        data = data.decode('latin-1').encode('utf-16LE')
        data = cipher.encrypt(pad(data, block_size=0x10))
        data = base64.b16encode(data).lower().decode('ascii')
        ivec = base64.b64encode(ivec).decode('ascii')
        data = '|'.join(('%d' % self._PSVER, ivec, data)).encode('utf-16LE')
        return base64.b64encode(self._MAGIC + data)

    def process(self, data):
        head, ivec, data = base64.b64decode(data).split(b'|\0')
        self.log_info('head:', head.hex())
        ivec = base64.b64decode(ivec.decode('utf-16LE'))
        self.log_info('ivec:', ivec.hex())
        data = base64.b16decode(data.decode('utf-16LE'), casefold=True)
        if len(data) % 0x10 != 0:
            self.log_info('data not block-aligned, padding with zeros')
            data += B'\0' * (0x10 - len(data) % 0x10)
        cipher = AES.new(self.key, AES.MODE_CBC, ivec)
        data = cipher.decrypt(data)
        try:
            data = unpad(data, block_size=0x10)
        except Exception:
            self.log_warn('decrypted data does not have PKCS7 padding')
        for p in range(0x10):
            try:
                return data[-p:].decode('utf-16LE').encode('latin-1')
            except UnicodeDecodeError:
                pass
            except UnicodeEncodeError:
                pass
        self.log_warn('result is not a padded unicode string, key is likely wrong')
        return data
