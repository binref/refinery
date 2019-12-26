#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Implements several popular block and stream ciphers.
"""
from typing import Iterable, Any
from Crypto.Util.Padding import pad, unpad

from ... import Unit, Executable, RefineryCriticalException, RefineryPartialResult
from ....lib.argformats import multibin, OptionFactory, extract_options


class CipherExecutable(Executable):
    """
    A metaclass for the abstract class `refinery.units.crypto.cipher.CipherUnit` which
    normalizes the class variable `__key_sizes__` containing an iterable of all possible
    key sizes that are acceptable for the represented cipher.
    """
    def __init__(cls, name, bases, nmspc, abstract=False):

        if cls.__key_sizes__:
            try:
                iter(cls.__key_sizes__)
            except TypeError:
                cls.__key_sizes__ = (cls.__key_sizes__,)
        else:
            cls.__key_sizes__ = ()

        return super(CipherExecutable, cls).__init__(
            name, bases, nmspc, abstract=abstract
        )


class CipherUnit(Unit, metaclass=CipherExecutable, abstract=True):
    __blocksize__ = 1
    __key_sizes__ = None

    @property
    def __stream__(self) -> bool:
        return self.__blocksize__ == 1

    @property
    def maximum_key_size(self) -> int:
        return max(self.__key_sizes__)

    def interface(self, argp):

        if self.__blocksize__ > 1:
            argp.add_argument(
                '-b', '--block-align', action='store_true', help=(
                    F'Pad all input data with zero bytes to a multiple of the block '
                    F'size ({self.__blocksize__} bytes).'
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

        if not self.__stream__:
            argp.add_argument('--iv', type=multibin, default=bytes(self.__blocksize__), nargs='?',
                help='Specifies the initialization vector. If none is specified, then a block of zero bytes is used.')

        return super().interface(argp)

    def __init__(self, *args, **kw):
        if self.__key_sizes__:
            try:
                iter(self.__key_sizes__)
            except TypeError:
                self.__key_sizes__ = (self.__key_sizes__,)
        else:
            self.__key_sizes__ = ()
        super().__init__(*args, **kw)

    @property
    def key_size_chosen(self) -> int:
        try:
            return self.args.key_size
        except AttributeError:
            return self.maximum_key_size

    @property
    def key(self) -> bytes:
        return self.args.key

    @property
    def iv(self) -> bytes:
        if not self.__stream__ and len(self.args.iv) != self.__blocksize__:
            raise ValueError(
                F'The IV has length {len(self.args.iv)} but the block size '
                F'is {self.__blocksize__}.'
            )
        return self.args.iv

    def decrypt(self, data: bytes) -> bytes:
        raise NotImplementedError

    def encrypt(self, data: bytes) -> bytes:
        raise NotImplementedError

    def _zpad(self, data):
        if not self.__stream__ and self.args.block_align:
            overhang = len(data) % self.__blocksize__
            if overhang:
                padding = self.__blocksize__ - overhang
                self.log_info(F'appending {padding} padding null bytes')
                return data + B'\0' * padding
        return data

    def reverse(self, data: bytes) -> bytes:
        data = self._zpad(data)
        if not self.__stream__ and self.args.padding:
            padding = self.args.padding[0]
            if padding != 'RAW':
                self.log_info('padding method:', padding)
                data = pad(data, self.__blocksize__, padding.lower())
        data = self.encrypt(data)
        return data

    def process(self, data: bytes) -> bytes:
        return self.unpad(self.decrypt(self._zpad(data)))

    def unpad(self, data: bytes) -> bytes:
        if self.__stream__ or not self.args.padding:
            return data
        for p in self.args.padding:
            if p == 'RAW':
                return data
            try:
                return unpad(data, self.__blocksize__, p.lower())
            except Exception:
                pass
        else:
            raise RefineryPartialResult(
                'none of these paddings worked: ' + ', '.join(self.args.padding),
                partial=data
            )


class StandardCipherExecutable(CipherExecutable):

    def __new__(mcs, name, bases, nmspc, cipher=None):
        return super(StandardCipherExecutable, mcs).__new__(
            mcs, name, bases, nmspc, abstract=not cipher)

    def __init__(cls, name, bases, nmspc, cipher=None):
        abstract = not cipher
        if not abstract:
            cls.__cipher__ = cipher
            cls.__blocksize__ = cipher.block_size
            cls.__key_sizes__ = cipher.key_size
        else:
            cls.__cipher__ = NotImplemented
        return super(StandardCipherExecutable, cls).__init__(
            name, bases, nmspc, abstract=abstract)


class StandardCipherUnit(CipherUnit, metaclass=StandardCipherExecutable):

    def interface(self, argp):
        if not self.__stream__:
            modes = extract_options(self.__cipher__)
            if not modes:
                raise RefineryCriticalException(
                    F'cipher {self.__cipher__.__name__} is a block cipher module '
                    F'but no cipher block mode constants were found.'
                )
            argp.add_argument('mode', type=OptionFactory(modes), metavar='mode', choices=list(modes), help=(
                'Choose cipher mode to be used. Possible values are: {}.'.format(', '.join(modes))
            ))
        return super().interface(argp)

    def _get_cipher_instance(self, **optionals) -> Any:
        self.log_info(F'encryption key:', self.key.hex())
        if not self.__stream__:
            if not self.args.mode.name == 'ECB':
                optionals['IV'] = self.iv
                self.log_info('initial vector:', self.iv.hex())
            if self.args.mode:
                optionals['mode'] = self.args.mode.value
        try:
            return self.__cipher__.new(key=self.key, **optionals)
        except TypeError:
            # occurs when this mode requires no IV
            optionals.pop('IV')
            if self.iv:
                self.log_info('ignoring IV for mode', self.args.mode)
            return self.__cipher__.new(key=self.key, **optionals)

    def encrypt(self, data: bytes) -> bytes:
        return self._get_cipher_instance().encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        return self._get_cipher_instance().decrypt(data)


class StreamCipherUnit(CipherUnit, abstract=True):

    def __stream__(self) -> bool:
        return True

    def keystream(self) -> Iterable[bytes]:
        raise NotImplementedError

    def encrypt(self, data: bytes) -> bytes:
        key = iter(self.keystream())
        return bytes(b ^ next(key) for b in data)

    decrypt = encrypt


class LatinStreamCipher(StandardCipherUnit):

    def interface(self, argp):
        argp.add_argument('-N', '--nonce', default=B'REFINERY', type=multibin,
            help='Specify the one-time use nonce; the default value is "REFINERY".')
        return super().interface(argp)

    def _get_cipher_instance(self, **optionals) -> Any:
        self.log_info(F'one-time nonce:', self.args.nonce.hex())
        return super()._get_cipher_instance(nonce=self.args.nonce)
