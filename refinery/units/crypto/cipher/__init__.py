#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Implements several popular block and stream ciphers.
"""
import abc

from typing import (
    Any,
    ByteString,
    ClassVar,
    Iterable,
    Optional,
    Tuple,
    Type,
)
from refinery.lib.crypto import (
    CipherObjectFactory,
    CipherInterface,
)
from refinery.lib.argformats import (
    Option,
    extract_options,
    OptionFactory,
)
from refinery.units import (
    arg,
    Executable,
    RefineryCriticalException,
    RefineryPartialResult,
    Unit,
)


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

    @Unit.Requires('numpy')
    def _numpy():
        import numpy
        return numpy

    def encrypt(self, data: bytearray) -> bytearray:
        it = self._keystream or self.keystream()
        try:
            np = self._numpy
        except ImportError:
            self.log_info('this unit could perform faster if numpy was installed.')
            out = bytearray(a ^ b for a, b in zip(it, data))
        else:
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
        self, key, iv: arg('-i', '--iv', help=(
            'Specifies the initialization vector. If none is specified, then a block of zero bytes is used.')) = B'',
        padding: arg.choice('-p', type=str.lower, choices=['pkcs7', 'iso7816', 'x923', 'raw'],
            nargs=1, metavar='P', help=(
            'Choose a padding algorithm ({choices}). The raw algorithm does nothing. By default, all other algorithms '
            'are attempted. In most cases, the data was not correctly decrypted if none of these work.')
        ) = None,
        raw: arg.switch('-r', '--raw', help='Set the padding to raw; ignored when a padding is specified.') = False,
        **keywords
    ):
        if not padding:
            padding = ['raw'] if raw else ['pkcs7', 'iso7816', 'x923']
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
        if padding != 'raw':
            data = pad(data, self.blocksize, padding)
        return super().reverse(data)

    def process(self, data: ByteString) -> ByteString:
        from Crypto.Util.Padding import unpad
        result = super().process(data)
        for p in self.args.padding:
            if p == 'raw':
                return result
            try:
                unpadded = unpad(result, self.blocksize, p.lower())
            except Exception:
                pass
            else:
                self.log_info(F'unpadding worked using {p}')
                return unpadded
        raise RefineryPartialResult(
            'None of these paddings worked: {}'.format(', '.join(self.args.padding)),
            partial=result)


class StandardCipherExecutable(CipherExecutable):

    _available_block_cipher_modes: ClassVar[Type[Option]]
    _cipher_object_factory: ClassVar[CipherObjectFactory]

    def __new__(mcs, name, bases, nmspc, cipher: Optional[CipherObjectFactory] = None):
        if cipher is None:
            keywords = dict(abstract=True)
        else:
            keywords = dict(
                abstract=False,
                blocksize=cipher.block_size,
                key_sizes=cipher.key_size,
            )
        return super(StandardCipherExecutable, mcs).__new__(mcs, name, bases, nmspc, **keywords)

    def __init__(cls, name, bases, nmspc, cipher: Optional[CipherObjectFactory] = None):
        cls: Executable
        abstract = cipher is None
        super(StandardCipherExecutable, cls).__init__(
            name, bases, nmspc, abstract=abstract)
        cls._cipher_object_factory = cipher
        if abstract or cipher.block_size <= 1 or 'mode' not in cls._argument_specification:
            return
        modes = extract_options(cipher)
        if not modes:
            raise RefineryCriticalException(
                F'The cipher {cipher.name} is a block cipher module, '
                F'but no cipher block mode constants were found.'
            )
        cls._available_block_cipher_modes = OptionFactory(modes, ignorecase=True)
        cls._argument_specification['mode'].merge_all(arg(
            '-m', '--mode', type=str.upper, metavar='M', nargs=arg.delete, choices=list(modes),
            help=(
                'Choose cipher mode to be used. Possible values are: {}. By default, the CBC mode'
                '  is used when an IV is is provided, and ECB otherwise.'.format(', '.join(modes))
            )
        ))


class StandardCipherUnit(CipherUnit, metaclass=StandardCipherExecutable):

    _available_block_cipher_modes: ClassVar[Type[Option]]
    _cipher_object_factory: ClassVar[CipherObjectFactory]

    def _get_cipher_instance(self, **optionals) -> CipherInterface:
        self.log_info(lambda: F'encryption key: {self.args.key.hex()}')
        return self._cipher_object_factory.new(key=self.args.key, **optionals)

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

    def __init__(self, key, iv=B'', padding=None, mode=None, raw=False):
        mode = self._available_block_cipher_modes(mode or iv and 'CBC' or 'ECB')
        if iv and mode.name == 'ECB':
            raise ValueError('No initialization vector can be specified for ECB mode.')
        super().__init__(key=key, iv=iv, padding=padding, mode=mode, raw=raw)

    def _get_cipher_instance(self, **optionals) -> CipherInterface:
        mode = self.args.mode.name
        if mode != 'ECB':
            iv = bytes(self.iv)
            if mode == 'CTR' and len(iv) == self.blocksize:
                from Crypto.Util import Counter
                counter = Counter.new(self.blocksize * 8,
                    initial_value=int.from_bytes(iv, 'big'))
                optionals['counter'] = counter
            elif mode in ('CCM', 'EAX', 'GCM', 'SIV', 'OCB', 'CTR'):
                bounds = {
                    'CCM': (7, self.blocksize - 2),
                    'OCB': (1, self.blocksize),
                    'CTR': (1, self.blocksize),
                }.get(mode, None)
                if bounds and len(iv) not in range(*bounds):
                    raise ValueError(F'Invalid nonce length, must be in {bounds} for {mode}.')
                optionals['nonce'] = iv
            elif mode in ('PCBC', 'CBC', 'CFB', 'OFB', 'OPENPGP'):
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
            return self._cipher_object_factory.new(key=self.args.key, **optionals)


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
