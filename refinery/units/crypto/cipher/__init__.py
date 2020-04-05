#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Implements several popular block and stream ciphers.
"""
from typing import Iterable, Any, ByteString
from Crypto.Util.Padding import pad, unpad

from ... import arg, Unit, Executable, RefineryCriticalException, RefineryPartialResult
from ....lib.argformats import OptionFactory, extract_options


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


class CipherUnit(Unit, metaclass=CipherExecutable, abstract=True):

    def __init__(self, key: arg.help('The encryption key.'), **keywords):
        super().__init__(key=key, **keywords)

    @property
    def key_size_chosen(self) -> int:
        try:
            return self.args.key_size
        except AttributeError:
            return self.maximum_key_size

    @property
    def maximum_key_size(self) -> int:
        return max(self.key_sizes)

    @property
    def key(self) -> ByteString:
        return self.args.key

    def decrypt(self, data: ByteString) -> ByteString:
        raise NotImplementedError

    def encrypt(self, data: ByteString) -> ByteString:
        raise NotImplementedError

    def process(self, data: ByteString) -> ByteString:
        return self.decrypt(data)

    def reverse(self, data: ByteString) -> ByteString:
        return self.encrypt(data)


class StreamCipherUnit(CipherUnit, abstract=True):

    def __init__(self, key):
        super().__init__(key=key)

    def keystream(self) -> Iterable[int]:
        raise NotImplementedError

    def encrypt(self, data: bytearray) -> bytearray:
        import numpy as np
        key = np.fromiter(
            self.keystream(), dtype=np.uint8, count=len(data))
        out = np.frombuffer(
            memoryview(data), dtype=np.uint8, count=len(data))
        out ^= key
        return out

    decrypt = encrypt


class BlockCipherUnitBase(CipherUnit, abstract=True):
    def __init__(
        self, key, iv: arg('-I', '--iv', help=(
            'Specifies the initialization vector. If none is specified, then a block '
            'of zero bytes is used.')) = B'',
        padding: arg.choice('-P', choices=['PKCS7', 'ISO7816', 'X923', 'RAW'],
            nargs=1, metavar='ALG', help=(
            'Choose a padding algorithm ({choices}). The RAW algorithm does nothing. '
            'By default, all other algorithms are attempted. In most cases, the data '
            'was not correctly decrypted if none of these work.')
        ) = None,
        **keywords
    ):
        if not padding:
            padding = ['PKCS7', 'ISO7816', 'X923']
        elif not isinstance(padding, list):
            padding = [padding]
        iv = iv or bytes(self.blocksize)
        super().__init__(key=key, iv=iv, padding=padding, **keywords)

    @property
    def iv(self) -> ByteString:
        if len(self.args.iv) != self.blocksize:
            raise ValueError(
                F'The IV has length {len(self.args.iv)} but the block size '
                F'is {self.blocksize}.'
            )
        return self.args.iv

    def reverse(self, data: ByteString) -> ByteString:
        padding = self.args.padding[0]
        if padding != 'RAW':
            self.log_info('padding method:', padding)
            data = pad(data, self.blocksize, padding.lower())
        return super().reverse(data)

    def process(self, data: ByteString) -> ByteString:
        result = super().process(data)
        for p in self.args.padding:
            if p == 'RAW':
                return result
            try:
                return unpad(result, self.blocksize, p.lower())
            except Exception:
                pass
        raise RefineryPartialResult(
            'None of these paddings worked: {}'.format(', '.join(self.args.padding)),
            partial=result)


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
        super(StandardCipherExecutable, cls).__init__(
            name, bases, nmspc, abstract=cipher is NotImplemented)
        cls.stdcipher = cipher
        if cipher is not NotImplemented and cipher.block_size > 1 and 'mode' in cls.argspec:
            modes = extract_options(cipher)
            if not modes:
                raise RefineryCriticalException(
                    F'The cipher {cipher.__name__} is a block cipher module, '
                    F'but no cipher block mode constants were found.'
                )
            cls.modespec = OptionFactory(modes)
            cls.argspec['mode'].merge_all(arg(
                dest='mode', type=str, metavar='mode', choices=list(modes),
                help='Choose cipher mode to be used. Possible values are: {}.'.format(', '.join(modes))
            ))


class StandardCipherUnit(CipherUnit, metaclass=StandardCipherExecutable):

    def __init__(self, key, **keywords):
        super().__init__(key, **keywords)

    def _get_cipher_instance(self, **optionals) -> Any:
        self.log_info(F'encryption key:', self.key.hex())
        return self.stdcipher.new(key=self.key, **optionals)

    def encrypt(self, data: bytes) -> bytes:
        return self._get_cipher_instance().encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        return self._get_cipher_instance().decrypt(data)


class StandardBlockCipherUnit(BlockCipherUnitBase, StandardCipherUnit):

    def __init__(self, mode, key, iv=None, padding=None):
        super().__init__(key=key, iv=iv, padding=padding, mode=self.modespec(mode))

    def _get_cipher_instance(self, **optionals) -> Any:
        if not self.args.mode.name == 'ECB':
            optionals['IV'] = self.iv
            self.log_info('initial vector:', self.iv.hex())
        if self.args.mode:
            optionals['mode'] = self.args.mode.value
        try:
            return super()._get_cipher_instance(**optionals)
        except TypeError:
            if 'IV' not in optionals:
                raise
            del optionals['IV']
            if self.iv:
                self.log_info('ignoring IV for mode', self.args.mode)
            return self.stdcipher.new(key=self.key, **optionals)


class LatinStreamCipher(StandardCipherUnit):

    def __init__(self, key, nonce:
        arg('-N', help='Specify the one-time use nonce; the default value is "REFINERY".') = B'REFINERY'
    ):
        super().__init__(key, nonce=nonce)

    def _get_cipher_instance(self, **optionals) -> Any:
        self.log_info(F'one-time nonce:', self.args.nonce.hex())
        return super()._get_cipher_instance(nonce=self.args.nonce)
