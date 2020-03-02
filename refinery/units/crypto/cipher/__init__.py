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
    normalizes the class variable `key_sizes` containing an iterable of all possible
    key sizes that are acceptable for the represented cipher.
    """

    def __new__(mcs, name, bases, nmspc, abstract=False, blocksize=1, key_sizes=None):
        nmspc.setdefault('blocksize', blocksize)
        nmspc.setdefault('key_sizes', key_sizes)
        return super(CipherExecutable, mcs).__new__(mcs, name, bases, nmspc, abstract=abstract)

    def __init__(cls, name, bases, nmspc, abstract=False, **_):
        cls.key_sizes = (cls.key_sizes,) if isinstance(cls.key_sizes, int) else tuple(cls.key_sizes or ())
        super(CipherExecutable, cls).__init__(name, bases, nmspc, abstract=abstract)

    @property
    def streaming(cls):
        return cls.blocksize == 1


class CipherUnit(Unit, metaclass=CipherExecutable, abstract=True):

    @property
    def maximum_key_size(self) -> int:
        return max(self.key_sizes)

    @property
    def streaming(self):
        return self.__class__.streaming

    @classmethod
    def interface(cls, argp):

        if cls.blocksize > 1:
            argp.add_argument(
                '-b', '--block-align', action='store_true', help=(
                    F'Pad all input data with zero bytes to a multiple of the block '
                    F'size ({cls.blocksize} bytes).'
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

        if not cls.streaming:
            argp.add_argument('--iv', type=multibin, default=bytes(cls.blocksize), nargs='?',
                help='Specifies the initialization vector. If none is specified, then a block of zero bytes is used.')

        return super().interface(argp)

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
        if not self.streaming and len(self.args.iv) != self.blocksize:
            raise ValueError(
                F'The IV has length {len(self.args.iv)} but the block size '
                F'is {self.blocksize}.'
            )
        return self.args.iv

    def decrypt(self, data: bytes) -> bytes:
        raise NotImplementedError

    def encrypt(self, data: bytes) -> bytes:
        raise NotImplementedError

    def _zpad(self, data):
        if not self.streaming and self.args.block_align:
            overhang = len(data) % self.blocksize
            if overhang:
                padding = self.blocksize - overhang
                self.log_info(F'appending {padding} padding null bytes')
                return data + B'\0' * padding
        return data

    def reverse(self, data: bytes) -> bytes:
        data = self._zpad(data)
        if not self.streaming and self.args.padding:
            padding = self.args.padding[0]
            if padding != 'RAW':
                self.log_info('padding method:', padding)
                data = pad(data, self.blocksize, padding.lower())
        data = self.encrypt(data)
        return data

    def process(self, data: bytes) -> bytes:
        return self.unpad(self.decrypt(self._zpad(data)))

    def unpad(self, data: bytes) -> bytes:
        if self.streaming or not self.args.padding:
            return data
        for p in self.args.padding:
            if p == 'RAW':
                return data
            try:
                return unpad(data, self.blocksize, p.lower())
            except Exception:
                pass
        else:
            raise RefineryPartialResult(
                'none of these paddings worked: ' + ', '.join(self.args.padding),
                partial=data
            )


class StandardCipherExecutable(CipherExecutable):

    def __new__(mcs, name, bases, nmspc, cipher=NotImplemented):
        if cipher is NotImplemented:
            keywords = dict(abstract=True)
        else:
            keywords = dict(
                abstract=False,
                blocksize=cipher.block_size,
                key_sizes=cipher.key_size,
            )
        return super(StandardCipherExecutable, mcs).__new__(mcs, name, bases, nmspc, **keywords)

    def __init__(cls, name, bases, nmspc, cipher=NotImplemented):
        cls.stdcipher = cipher
        super(StandardCipherExecutable, cls).__init__(name, bases, nmspc, abstract=cipher is NotImplemented)


class StandardCipherUnit(CipherUnit, metaclass=StandardCipherExecutable):

    @classmethod
    def interface(cls, argp):
        if not cls.streaming:
            modes = extract_options(cls.stdcipher)
            if not modes:
                raise RefineryCriticalException(
                    F'cipher {cls.stdcipher.__name__} is a block cipher module '
                    F'but no cipher block mode constants were found.'
                )
            argp.add_argument('mode', type=OptionFactory(modes), metavar='mode', choices=list(modes), help=(
                'Choose cipher mode to be used. Possible values are: {}.'.format(', '.join(modes))
            ))
        return super().interface(argp)

    def _get_cipher_instance(self, **optionals) -> Any:
        self.log_info(F'encryption key:', self.key.hex())
        if not self.streaming:
            if not self.args.mode.name == 'ECB':
                optionals['IV'] = self.iv
                self.log_info('initial vector:', self.iv.hex())
            if self.args.mode:
                optionals['mode'] = self.args.mode.value
        try:
            return self.stdcipher.new(key=self.key, **optionals)
        except TypeError:
            # occurs when this mode requires no IV
            optionals.pop('IV')
            if self.iv:
                self.log_info('ignoring IV for mode', self.args.mode)
            return self.stdcipher.new(key=self.key, **optionals)

    def encrypt(self, data: bytes) -> bytes:
        return self._get_cipher_instance().encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        return self._get_cipher_instance().decrypt(data)


class StreamCipherUnit(CipherUnit, abstract=True):

    def keystream(self) -> Iterable[bytes]:
        raise NotImplementedError

    def encrypt(self, data: bytes) -> bytes:
        key = iter(self.keystream())
        return bytes(b ^ next(key) for b in data)

    decrypt = encrypt


class LatinStreamCipher(StandardCipherUnit):

    @classmethod
    def interface(cls, argp):
        argp.add_argument('-N', '--nonce', default=B'REFINERY', type=multibin,
            help='Specify the one-time use nonce; the default value is "REFINERY".')
        return super().interface(argp)

    def _get_cipher_instance(self, **optionals) -> Any:
        self.log_info(F'one-time nonce:', self.args.nonce.hex())
        return super()._get_cipher_instance(nonce=self.args.nonce)
