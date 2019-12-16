#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Implements several popular block and stream ciphers.
"""
from typing import Iterable, Any
from Crypto.Util.Padding import pad, unpad

from ... import Unit
from ....lib.argformats import multibin, OptionFactory, extract_options


class CipherUnit(Unit, abstract=True):
    _requires_iv = False
    _block_size = 1
    _block_cipher_modes = None
    _possible_key_sizes = None

    def interface(self, argp):
        if not self._block_cipher_modes:
            argp.set_defaults(mode=None)
        else:
            argp.add_argument(
                'mode', type=OptionFactory(self._block_cipher_modes), metavar='mode',
                choices=list(self._block_cipher_modes), help=(
                    'Choose cipher mode to be used. Possible values are: {}.'.format(
                        ', '.join(self._block_cipher_modes)
                    )
                )
            )

        if self._block_size > 1:
            argp.add_argument(
                '-b', '--block-align', action='store_true', help=(
                    F'Pad all input data with zero bytes to a multiple of the block '
                    F'size ({self._block_size} bytes).'
                )
            )

            pdng = argp.add_mutually_exclusive_group()
            popt = ['PKCS7', 'ISO7816', 'X923', 'RAW']
            pdng.add_argument(
                '-P', '--padding', dest='padding', choices=popt,
                default=popt[:-1], metavar='ALG', nargs=1, help=(
                    F'Choose a padding algorithm ({", ".join(popt)}). The RAW algorithm does '
                    F'nothing. By default, all other algorithms are attempted. In most cases, '
                    F'the data was not correctly decrypted if none of these work.'
                )
            )

        argp.add_argument('key', type=multibin, help='encryption key')

        if self._requires_iv:
            argp.add_argument('--iv', type=multibin, default=bytes(self._block_size), nargs='?',
                help='Specifies the initialization vector. If none is specified, then a block of zero bytes is used.')

        return super().interface(argp)

    def __init__(self, *args, **kw):
        if self._possible_key_sizes:
            try:
                iter(self._possible_key_sizes)
            except TypeError:
                self._possible_key_sizes = (self._possible_key_sizes,)
        else:
            self._possible_key_sizes = ()
        super().__init__(*args, **kw)

    @property
    def key_max_size(self) -> int:
        try:
            return max(self._possible_key_sizes)
        except Exception:
            return None

    @property
    def key_size_chosen(self) -> int:
        try:
            return self.args.key_size
        except AttributeError:
            return self.key_max_size

    @property
    def key(self) -> bytes:
        return self.args.key

    @property
    def iv(self) -> bytes:
        if self._block_size > 1 and len(self.args.iv) != self._block_size:
            raise ValueError(
                F'The IV has length {len(self.args.iv)} but the block size '
                F'is {self._block_size}.'
            )
        return self.args.iv

    def decrypt(self, data: bytes) -> bytes:
        raise NotImplementedError

    def encrypt(self, data: bytes) -> bytes:
        raise NotImplementedError

    def _zpad(self, data):
        if self._block_size > 1 and self.args.block_align:
            overhang = len(data) % self._block_size
            if overhang:
                padding = self._block_size - overhang
                self.log_info(F'appending {padding} padding null bytes')
                return data + B'\0' * padding
        return data

    def reverse(self, data: bytes) -> bytes:
        data = self._zpad(data)
        if self._block_size > 1 and self.args.padding:
            padding = self.args.padding[0]
            if padding != 'RAW':
                self.log_info('padding method:', padding)
                data = pad(data, self._block_size, padding.lower())
        data = self.encrypt(data)
        return data

    def process(self, data: bytes) -> bytes:
        return self.unpad(self.decrypt(self._zpad(data)))

    def unpad(self, data: bytes) -> bytes:
        if self._block_size == 1 or not self.args.padding:
            return data
        for p in self.args.padding:
            if p == 'RAW':
                return data
            try:
                return unpad(data, self._block_size, p.lower())
            except Exception:
                pass
        else:
            self.log_warn('none of these paddings worked: ' + ', '.join(self.args.padding))
            return data


class StandardCipherUnit(CipherUnit, abstract=True):
    _cipher = None

    def __init__(self, *args, **kw):
        if self._block_size == 1 and self._cipher.block_size > 1:
            self._block_size = self._cipher.block_size
        if not self._possible_key_sizes:
            self._possible_key_sizes = self._cipher.key_size
        self._block_cipher_modes = extract_options(self._cipher)
        super().__init__(*args, **kw)

    @property
    def cipher_instance(self) -> Any:
        self.log_info(F'encryption key:', self.key.hex())
        optionals = {}
        if self._requires_iv and not self.args.mode.name == 'ECB':
            optionals['IV'] = self.iv
            self.log_info('initial vector:', self.iv.hex())
        if self.args.mode:
            optionals['mode'] = self.args.mode.value
        try:
            return self._cipher.new(self.key, **optionals)
        except TypeError:
            # occurs when this mode requires no IV
            optionals.pop('IV')
            if self.iv:
                self.log_info('ignoring IV for mode', self.args.mode)
            return self._cipher.new(self.key, **optionals)

    def encrypt(self, data: bytes) -> bytes:
        return self.cipher_instance.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        return self.cipher_instance.decrypt(data)


class StreamCipherUnit(CipherUnit, abstract=True):

    def keystream(self) -> Iterable[bytes]:
        raise NotImplementedError()

    def encrypt(self, data: bytes) -> bytes:
        key = iter(self.keystream())
        return bytes(b ^ next(key) for b in data)

    decrypt = encrypt


class NonceToIV:
    def __init__(self, module, nonce_default=B'REFINERY'):
        self.__module = module
        self.__nonce_default = nonce_default

    def new(self, key, IV=None):
        if IV is None:
            return self.__module.new(key=key, nonce=self.__nonce_default)
        else:
            return self.__module.new(key=key, nonce=IV)

    def __getattr__(self, value):
        return getattr(self.__module, value)
