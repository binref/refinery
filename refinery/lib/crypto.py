#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Primitives used in custom cryptographic implementations.
"""
from __future__ import annotations

from typing import Callable, ClassVar, Container, Generator, Optional, Type, Union, Dict
from abc import ABC, abstractmethod
from enum import Enum

BufferType = Union[bytearray, bytes, memoryview]
CIPHER_MODES: Dict[str, CipherMode] = {}


def strxor(a: bytes, b: bytes):
    """
    Return the XOR of the two byte strings `a` and `b`. The shorter of the two strings defines the
    length of the output.
    """
    return bytes(a ^ b for a, b in zip(a, b))


def _register_cipher_mode(cls: Type[CipherMode]):
    cls._identifier = len(CIPHER_MODES)
    CIPHER_MODES[cls.__name__] = cls
    return cls


def rotl128(x: int, c: int):
    """
    Rotate the 128-bit integer `x` by `c` positions to the left.
    """
    return ((x << c) | (x >> (0x80 - c))) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF


def rotl64(x: int, c: int):
    """
    Rotate the 64-bit integer `x` by `c` positions to the left.
    """
    return ((x << c) | (x >> (0x40 - c))) & 0xFFFFFFFFFFFFFFFF


def rotl32(x: int, c: int):
    """
    Rotate the 32-bit integer `x` by `c` positions to the left.
    """
    return ((x << c) | (x >> (0x20 - c))) & 0xFFFFFFFF


def rotl16(x: int, c: int):
    """
    Rotate the 16-bit integer `x` by `c` positions to the left.
    """
    return ((x << c) | (x >> (0x10 - c))) & 0xFFFF


def rotl8(x: int, c: int):
    """
    Rotate the byte `x` by `c` positions to the left.
    """
    return ((x << c) | (x >> (0x08 - c))) & 0xFF


def rotr128(x: int, c: int):
    """
    Rotate the 128-bit integer `x` by `c` positions to the right.
    """
    return (x << (0x80 - c) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF) | (x >> c)


def rotr64(x: int, c: int):
    """
    Rotate the 64-bit integer `x` by `c` positions to the right.
    """
    return (x << (0x40 - c) & 0xFFFFFFFFFFFFFFFF) | (x >> c)


def rotr32(x: int, c: int):
    """
    Rotate the 32-bit integer `x` by `c` positions to the right.
    """
    return (x << (0x20 - c) & 0xFFFFFFFF) | (x >> c)


def rotr16(x: int, c: int):
    """
    Rotate the 16-bit integer `x` by `c` positions to the right.
    """
    return (x << (0x10 - c) & 0xFFFF) | (x >> c)


def rotr8(x: int, c: int):
    """
    Rotate the byte `x` by `c` positions to the right.
    """
    return (x << (0x08 - c) & 0xFF) | (x >> c)


def rotr(n: int, x: int, c: int) -> int:
    """
    Rotate the `n`-bit integer `x` by `c` positions to the right. If `n` is among the common bit
    sizes 8, 16, 32, 64, or 128, then one of the more specific functions in this module should be
    used instead.
    """
    mask = (1 << n) - 1
    c %= n
    return (x >> c) | (x << (n - c) & mask)


def rotl(n: int, x: int, c: int) -> int:
    """
    Rotate the `n`-bit integer `x` by `c` positions to the left. If `n` is among the common bit
    sizes 8, 16, 32, 64, or 128, then one of the more specific functions in this module should be
    used instead.
    """
    mask = (1 << n) - 1
    c %= n
    return (x >> (n - c)) | (x << c & mask)


class Operation(str, Enum):
    """
    Specifies whether data is currently being encrypted or decrypted.
    """
    Encrypt = 'encrypt'
    Decrypt = 'decrypt'


class CipherMode(ABC):
    """
    Abstract base class for a cipher mode of operation.
    """

    encrypt_block: Callable[[memoryview], memoryview]
    decrypt_block: Callable[[memoryview], memoryview]
    aligned: bool = True
    _identifier: ClassVar[int]

    @abstractmethod
    def encrypt(self) -> Generator[memoryview, memoryview, None]:
        """
        Implements data encryption according to the current cipher mode and underlying cipher.
        """
        raise NotImplementedError

    @abstractmethod
    def decrypt(self) -> Generator[memoryview, memoryview, None]:
        """
        Implements data decryption according to the current cipher mode and underlying cipher.
        """
        raise NotImplementedError

    def apply(
        self,
        operation: Operation,
        dst: memoryview,
        src: memoryview,
        encrypt_block: Callable[[memoryview], memoryview],
        decrypt_block: Callable[[memoryview], memoryview],
        blocksize: int,
    ) -> memoryview:
        """
        This method is used to perform a cryptographic `refinery.lib.crypto.Operation` to a given
        source `src` and write the result to the memory at `dst` according to the current cipher
        mode. To this end, it requires the block encryption and decryption primitives of the
        underlying cipher and the current block size.
        """
        self.encrypt_block = encrypt_block
        self.decrypt_block = decrypt_block
        engine: Generator[memoryview, memoryview, None] = {
            Operation.Encrypt: self.encrypt,
            Operation.Decrypt: self.decrypt,
        }[operation]()
        next(engine)
        top, rest = divmod(len(src), blocksize)
        top *= blocksize
        for k in range(0, top, blocksize):
            dst[k:k + blocksize] = engine.send(src[k:k + blocksize])
        if rest:
            dst[-rest:] = engine.send(src[-rest:])[:rest]
        engine.close()
        return dst


@_register_cipher_mode
class ECB(CipherMode):
    """
    The Electronic Codebook (ECB) is the most simple cipher mode of operation. The underlying
    cipher is applied block-wise with no additional safeguards.
    """

    def decrypt(self) -> Generator[memoryview, memoryview, None]:
        M = None
        D = self.decrypt_block
        while True:
            C = yield M
            M = D(C)

    def encrypt(self) -> Generator[memoryview, memoryview, None]:
        C = None
        E = self.encrypt_block
        while True:
            M = yield C
            C = E(M)


class DataUnaligned(ValueError):
    """
    Raised when input data is unexpectedly unaligned to the current block size.
    """
    def __init__(self) -> None:
        super().__init__('Data not aligned to block size.')


class StatefulCipherMode(CipherMode):
    """
    A subclass of `refinery.lib.crypto.CipherMode` that holds a state while performing any of
    its cryptographic `refinery.lib.crypto.Operation`s.
    """

    iv: BufferType
    """
    The initial vector for the internal state of the cipher mode.
    """

    def __init__(self, iv: BufferType):
        self.iv = iv


@_register_cipher_mode
class CBC(StatefulCipherMode):
    """
    An implementation of the popular Cipher Block Chaining mode of operation.
    """

    def encrypt(self) -> Generator[memoryview, memoryview, None]:
        C = self.iv
        E = self.encrypt_block
        while True:
            M = yield C
            C = E(strxor(M, C))

    def decrypt(self) -> Generator[memoryview, memoryview, None]:
        S = self.iv
        M = None
        D = self.decrypt_block
        while True:
            C = yield M
            M = strxor(D(C), S)
            S = bytes(C)


@_register_cipher_mode
class PCBC(StatefulCipherMode):
    """
    An implementation of Propagating Cipher Block Chaining.
    """

    def encrypt(self) -> Generator[memoryview, memoryview, None]:
        S = self.iv
        C = None
        E = self.encrypt_block
        while True:
            M = yield C
            C = E(strxor(M, S))
            S = strxor(C, M)

    def decrypt(self) -> Generator[memoryview, memoryview, None]:
        S = self.iv
        M = None
        D = self.decrypt_block
        while True:
            C = yield M
            M = strxor(S, D(C))
            S = strxor(M, C)


@_register_cipher_mode
class CFB(CipherMode):
    """
    Cipher Feedback Mode: https://csrc.nist.gov/publications/detail/sp/800-38a/final
    """

    iv: BufferType
    segment_size: int
    aligned = False

    def __init__(self, iv: BufferType, segment_size: Optional[int] = None):
        if segment_size is None:
            segment_size = 8
        if segment_size % 8 != 0:
            raise NotImplementedError('segment sizes may only be multiples of 8')
        segment_size = segment_size // 8
        if len(iv) % segment_size != 0:
            raise NotImplementedError(
                F'the block size {len(iv) * 8} is not an even multiple of the segment '
                F'size {segment_size * 8}; this is currently not supported.')
        self.segment_size = segment_size
        self.iv = iv

    def encrypt(self) -> Generator[memoryview, memoryview, None]:
        s = self.segment_size
        S = bytearray(self.iv)
        E = self.encrypt_block
        C = bytearray(len(self.iv))
        if s == 1:
            while True:
                M = yield C
                for k, m in enumerate(M):
                    C[k] = c = m ^ E(S)[0]
                    S[:-1], S[-1] = memoryview(S)[1:], c
        else:
            segments = [slice(i, i + s) for i in range(0, len(S), s)]
            while True:
                M = yield C
                for k in segments:
                    m = M[k]
                    C[k] = c = strxor(m, E(S)[:s])
                    S[:-s], S[-s:] = memoryview(S)[s:], c

    def decrypt(self) -> Generator[memoryview, memoryview, None]:
        s = self.segment_size
        S = bytearray(self.iv)
        E = self.encrypt_block
        M = bytearray(len(self.iv))
        if s == 1:
            while True:
                C = yield M
                for k, c in enumerate(C):
                    M[k] = c ^ E(S)[0]
                    S[:-1], S[-1] = memoryview(S)[1:], c
        else:
            segments = [slice(i, i + s) for i in range(0, len(S), s)]
            while True:
                C = yield M
                for k in segments:
                    c = C[k]
                    M[k] = strxor(c, E(S)[:s])
                    S[:-s], S[-s:] = memoryview(S)[s:], c


@_register_cipher_mode
class OFB(StatefulCipherMode):
    """
    An implementation of Output Feedback Mode.
    """

    aligned = False

    def encrypt(self) -> Generator[memoryview, memoryview, None]:
        S = self.iv
        C = None
        E = self.encrypt_block
        while True:
            M = yield C
            S = E(S)
            C = strxor(M, S)

    decrypt = encrypt


@_register_cipher_mode
class CTR(CipherMode):
    """
    An implementation of Counter mode.
    """

    counter_len: int
    prefix: BufferType
    suffix: BufferType
    initial_value: int
    little_endian: bool
    block_size: int

    aligned = False

    @property
    def byte_order(self):
        return 'little' if self.little_endian else 'big'

    def __init__(
        self,
        block_size: Optional[int] = None,
        counter: Optional[Dict] = None,
        nonce: Optional[BufferType] = None,
        initial_value: Optional[int] = 0,
        little_endian: bool = False
    ):
        if counter is not None:
            self.initial_value = counter.get('initial_value', initial_value)
            self.little_endian = counter.get('little_endian', little_endian)
            self.prefix = counter['prefix']
            self.suffix = counter['suffix']
            self.counter_len = counter['counter_len']
            self.block_size = self.counter_len + len(self.prefix) + len(self.suffix)
            if block_size not in {None, self.block_size}:
                raise ValueError('Information in counter object does not align with block size.')
            return
        if block_size is None:
            raise ValueError('Unable to construct CTR mode object without block_size or counter argument.')

        self.initial_value = initial_value
        self.little_endian = little_endian
        self.suffix = B''
        self.block_size = block_size

        if nonce is not None:
            if len(nonce) > block_size:
                raise ValueError('Nonce length exceeds block length.')
            self.counter_len = block_size - len(nonce)
            self.prefix = nonce
        else:
            self.counter_len = block_size // 2
            self.prefix = B'\0' * (block_size - self.counter_len)

    def encrypt(self) -> Generator[memoryview, memoryview, None]:
        S = bytearray(self.block_size)
        J = slice(len(self.prefix), self.block_size - len(self.suffix))
        K = self.initial_value
        if self.prefix:
            S[:+len(self.prefix)] = self.prefix
        if self.suffix:
            S[-len(self.suffix):] = self.suffix
        C = None
        E = self.encrypt_block
        order = self.byte_order
        csize = self.counter_len
        mask = (1 << (csize * 8)) - 1
        while True:
            M = yield C
            S[J] = K.to_bytes(csize, order)
            K = K + 1 & mask
            C = strxor(E(S), M)

    decrypt = encrypt


class CipherInterface(ABC):
    """
    Abstract base class for refinery's block cipher interface.
    """

    key_size: Container[int]
    """
    A container containing all valid key sizes for this cipher.
    """

    block_size: int
    """
    The block size of this cipher.
    """

    @abstractmethod
    def encrypt(self, M: BufferType) -> BufferType: ...
    """
    Data encryption according to this cipher interface.
    """

    @abstractmethod
    def decrypt(self, C: BufferType) -> BufferType: ...
    """
    Data decryption according to this cipher interface.
    """


class CipherObjectFactory(ABC):
    """
    An abstract class to build `refinery.lib.crypto.CipherInterface`s from an asortment of
    cryptographic secrets and parameters.
    """

    name: str
    key_size: Optional[Container[int]] = None
    block_size: Optional[int] = None

    @abstractmethod
    def new(
        self,
        key: BufferType,
        iv: Optional[BufferType] = None,
        counter: Optional[int] = None,
        initial_value: Optional[int] = 0,
        nonce: Optional[BufferType] = None,
        mode: Optional[str] = None,
        segment_size: Optional[int] = None,
        block_size: Optional[int] = None,
        **cipher_args
    ) -> CipherInterface:
        """
        Build the actual `refinery.lib.crypto.CipherInterface` from the given input parameters.
        This mimics the PyCrypto interface for new ciphers in order to make the refinery factory
        cross-compatible with that library.
        """
        ...


class PyCryptoFactoryWrapper(CipherObjectFactory):
    """
    Wraps a PyCrypto module as a `refinery.lib.crypto.CipherObjectFactory`.
    """

    def __init__(self, module):
        self.module = module

    def new(self, *a, **k) -> CipherInterface:
        return self.module.new(*a, **k)

    @property
    def key_size(self):
        try:
            value = self.module.key_size
        except AttributeError:
            return None
        if isinstance(value, int):
            return {value}
        return value

    @property
    def block_size(self):
        try:
            value = self.module.block_size
        except AttributeError:
            return None
        return value

    def __repr__(self):
        return repr(self.module)

    def __dir__(self):
        return dir(self.module)

    def __getattr__(self, key):
        return getattr(self.module, key)


class BlockCipherFactory(CipherObjectFactory):
    """
    A `refinery.lib.crypto.CipherObjectFactory` for custom block ciphers.
    """

    cipher: Type[BlockCipher]

    def __init__(self, cipher: Type[BlockCipher]):
        self.cipher = cipher
        self._modes = []
        for name, mode in CIPHER_MODES.items():
            setattr(self, F'MODE_{name}', mode._identifier)
            self._modes.append(mode)

    def new(self, key, mode=None, **args) -> CipherInterface:
        if mode is not None:
            mode = self._modes[mode]
        mode_arguments = {}
        cipher = self.cipher
        for arg in ('iv', 'counter', 'initial_value', 'nonce', 'mode', 'segment_size'):
            try:
                mode_arguments[arg] = args.pop(arg)
            except KeyError:
                pass
        if mode is CTR:
            block_size = self.block_size
            if block_size is None:
                # This happens for ciphers that do not have a fixed block size, i.e. the
                # block size is truly an instance attribute and not a class property.
                # In this case, we create a temporary cipher object and use it to obtain
                # the true block size.
                block_size = cipher(key, ECB, **args).block_size
            mode_arguments.update(block_size=block_size)
        mode = mode(**mode_arguments)
        return cipher(key, mode, **args)

    @property
    def name(self):
        return self.cipher.__name__

    @property
    def key_size(self):
        try:
            value = self.cipher.key_size
        except AttributeError:
            return None
        if isinstance(value, property):
            return None
        return value

    @property
    def block_size(self):
        try:
            value = self.cipher.block_size
        except AttributeError:
            return None
        if not isinstance(value, int):
            return None
        return value


class BlockCipher(CipherInterface, ABC):
    block_size: int
    key: BufferType
    mode: CipherMode
    key_size: Container[int]

    def __init__(self, key: BufferType, mode: Optional[CipherMode]):
        if len(key) not in self.key_size:
            raise ValueError(F'The key size {len(key)} is not supported by {self.__class__.__name__.lower()}.')
        self.key = key
        self.mode = mode or ECB()

    @abstractmethod
    def block_encrypt(self, data: BufferType) -> BufferType:
        """
        Encryption of a single block of data.
        """
        raise NotImplementedError

    @abstractmethod
    def block_decrypt(self, data: BufferType) -> BufferType:
        """
        Decryption of a single block of data.
        """
        raise NotImplementedError

    def _apply_blockwise(self, operation: Operation, data: BufferType) -> BufferType:
        block_size = self.block_size
        mode = self.mode
        if len(data) % block_size != 0 and mode.aligned:
            raise DataUnaligned
        dst = src = memoryview(data)
        if dst.readonly:
            dst = bytearray(src)
        return mode.apply(
            operation,
            dst,
            src,
            self.block_encrypt,
            self.block_decrypt,
            block_size
        )

    def encrypt(self, data: BufferType) -> BufferType:
        """
        Encrypt the input data.
        """
        return self._apply_blockwise(Operation.Encrypt, data)

    def decrypt(self, data: BufferType) -> BufferType:
        """
        Decrypt the input data.
        """
        return self._apply_blockwise(Operation.Decrypt, data)
