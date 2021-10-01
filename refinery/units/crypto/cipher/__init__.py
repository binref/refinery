#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Implements several popular block and stream ciphers.
"""
import abc

from typing import Iterable, Any, ByteString, Tuple

from ... import arg, Unit, Executable, RefineryCriticalException, RefineryPartialResult
from ....lib.argformats import OptionFactory, extract_options


class CipherExecutable(Executable):
    """
    A metaclass for the abstract class `refinery.units.crypto.cipher.CipherUnit` which
    normalizes the class variable `key_sizes` containing an iterable of all possible
    key sizes that are acceptable for the represented cipher.
    """

    def __new__(mcs, name, bases: tuple, nmspc: dict, abstract=False, blocksize=1, key_sizes=None):
        nmspc.setdefault('blocksize', blocksize)
        nmspc.setdefault('key_sizes', key_sizes)
        return super(CipherExecutable, mcs).__new__(mcs, name, bases, nmspc, abstract=abstract)

    def __init__(cls, name, bases, nmspc, abstract=False, **_):
        cls.key_sizes = (cls.key_sizes,) if isinstance(cls.key_sizes, int) else tuple(cls.key_sizes or ())
        super(CipherExecutable, cls).__init__(name, bases, nmspc, abstract=abstract)


class CipherUnit(Unit, metaclass=CipherExecutable, abstract=True):

    def __init__(self, key: arg(help='The encryption key.'), **keywords):
        super().__init__(key=key, **keywords)

    @abc.abstractmethod
    def decrypt(self, data: ByteString) -> ByteString:
        raise NotImplementedError

    @abc.abstractmethod
    def encrypt(self, data: ByteString) -> ByteString:
        raise NotImplementedError

    def process(self, data: ByteString) -> ByteString:
        if self.key_sizes and len(self.args.key) not in self.key_sizes:
            raise ValueError(F'the given key has an invalid length of {len(self.args.key)} bytes.')
        return self.decrypt(data)

    def reverse(self, data: ByteString) -> ByteString:
        return self.encrypt(data)


class StreamCipherUnit(CipherUnit, abstract=True):

    def __init__(
        self, key,
        stateful: arg.switch('-s', help='Do not reset the key stream while processing the chunks of one frame.') = False,
        **keywords
    ):
        super().__init__(key=key, stateful=stateful, **keywords)
        self._keystream = None

    @abc.abstractmethod
    def keystream(self) -> Iterable[int]:
        raise NotImplementedError

    def encrypt(self, data: bytearray) -> bytearray:
        import numpy as np
        it = self._keystream or self.keystream()
        key = np.fromiter(it, dtype=np.uint8, count=len(data))
        out = np.frombuffer(
            memoryview(data), dtype=np.uint8, count=len(data))
        out ^= key
        return out

    def filter(self, chunks: Iterable):
        if self.args.stateful:
            self._keystream = self.keystream()
        yield from chunks
        self._keystream = None

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
        return self.args.iv

    def reverse(self, data: ByteString) -> ByteString:
        from Crypto.Util.Padding import pad
        padding = self.args.padding[0]
        self.log_info('padding method:', padding)
        if padding != 'RAW':
            data = pad(data, self.blocksize, padding.lower())
        return super().reverse(data)

    def process(self, data: ByteString) -> ByteString:
        from Crypto.Util.Padding import unpad
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
        cls._stdcipher_ = cipher
        if cipher is not NotImplemented and cipher.block_size > 1 and 'mode' in cls._argspec_:
            modes = extract_options(cipher)
            if not modes:
                raise RefineryCriticalException(
                    F'The cipher {cipher.name} is a block cipher module, '
                    F'but no cipher block mode constants were found.'
                )
            cls._bcmspec_ = OptionFactory(modes, ignorecase=True)
            cls._argspec_['mode'].merge_all(arg(
                '-M', '--mode', type=str.upper, metavar='MODE', nargs=arg.delete, choices=list(modes),
                help=(
                    'Choose cipher mode to be used. Possible values are: {}. By default, the CBC mode'
                    '  is used when an IV is is provided, and ECB otherwise.'.format(', '.join(modes))
                )
            ))


class StandardCipherUnit(CipherUnit, metaclass=StandardCipherExecutable):

    def _get_cipher_instance(self, **optionals) -> Any:
        self.log_info(lambda: F'encryption key: {self.args.key.hex()}')
        return self._stdcipher_.new(key=self.args.key, **optionals)

    def encrypt(self, data: bytes) -> bytes:
        return self._get_cipher_instance().encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        cipher = self._get_cipher_instance()
        try:
            return cipher.decrypt(data)
        except ValueError:
            overlap = len(data) % self.blocksize
            if not overlap:
                raise
            data[-overlap:] = []
            self.log_warn(F'removing {overlap} bytes from the input to make it a multiple of the {self.blocksize}-byte block size')
            return cipher.decrypt(data)


class StandardBlockCipherUnit(BlockCipherUnitBase, StandardCipherUnit):

    blocksize: int
    key_sizes: Tuple[int, ...]

    def __init__(self, key, iv=B'', padding=None, mode=None):
        mode = self._bcmspec_(mode or iv and 'CBC' or 'ECB')
        if iv and mode.name == 'ECB':
            raise ValueError('No initialization vector can be specified for ECB mode.')
        super().__init__(key=key, iv=iv, padding=padding, mode=mode)

    def _get_cipher_instance(self, **optionals) -> Any:
        mode = self.args.mode.name
        if mode != 'ECB':
            iv = bytes(self.iv)
            if mode == 'CTR' and len(iv) == 16:
                from Crypto.Util import Counter
                counter = Counter.new(self.blocksize * 8,
                    initial_value=int.from_bytes(iv, 'big'))
                optionals['counter'] = counter
            elif mode in ('CCM', 'EAX', 'GCM', 'SIV', 'OCB', 'CTR'):
                bounds = {
                    'CCM': (7, 14),
                    'OCB': (1, 16),
                    'CTR': (1, 17),
                }.get(mode, None)
                if bounds and len(iv) not in range(*bounds):
                    raise ValueError(F'Invalid nonce length, must be in {bounds} for {mode}.')
                optionals['nonce'] = iv
            elif mode in ('CBC', 'CFB', 'OFB', 'OPENPGP'):
                if len(iv) > self.blocksize:
                    self.log_warn(F'The IV has length {len(self.args.iv)} and will be truncated to the blocksize {self.blocksize}.')
                    iv = iv[:self.blocksize]
                elif len(iv) < self.blocksize:
                    raise ValueError(F'The IV has length {len(self.args.iv)} but the block size is {self.blocksize}.')
                optionals['iv'] = iv
            self.log_info('initial vector:', iv.hex())
        if self.args.mode:
            optionals['mode'] = self.args.mode.value
        try:
            return super()._get_cipher_instance(**optionals)
        except TypeError:
            if 'iv' not in optionals:
                raise
            del optionals['iv']
            if self.iv:
                self.log_info('ignoring iv for mode', self.args.mode)
            return self._stdcipher_.new(key=self.args.key, **optionals)


class LatinCipherUnit(StreamCipherUnit, abstract=True):
    key_sizes = 16, 32

    def __init__(
        self, key,
        nonce: arg(help='The nonce. Default is the string {default}.') = B'REFINERY',
        magic: arg('-m', help='The magic constant; depends on the key size by default.') = B'',
        offset: arg.number('-x', help='Optionally specify the stream index, default is {default}.') = 0,
        rounds: arg.number('-r', help='The number of rounds. Has to be an even number.') = 20,
    ):
        super().__init__(key=key, nonce=nonce, magic=magic, offset=offset, rounds=rounds)


class LatinCipherStandardUnit(StandardCipherUnit):
    def __init__(self, key, nonce: arg(help='The nonce. Default is the string {default}.') = B'REFINERY'):
        super().__init__(key, nonce=nonce)

    def _get_cipher_instance(self, **optionals) -> Any:
        self.log_info('one-time nonce:', self.args.nonce.hex())
        return super()._get_cipher_instance(nonce=self.args.nonce)
