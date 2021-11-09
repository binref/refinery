#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import Callable, Container, Generator, Optional, Type, Union, Dict
from abc import ABC, abstractmethod
from enum import Enum

from Crypto.Util.strxor import strxor

BufferType = Union[bytearray, bytes, memoryview]
CIPHER_MODES: Dict[str, CipherMode] = {}


def _register_cipher_mode(cls):
    CIPHER_MODES[cls.__name__] = cls
    return cls


_DES_PARITYTABLE = bytearray((
    0x01, 0x01, 0x02, 0x02, 0x04, 0x04, 0x07, 0x07,
    0x08, 0x08, 0x0B, 0x0B, 0x0D, 0x0D, 0x0E, 0x0E,
    0x10, 0x10, 0x13, 0x13, 0x15, 0x15, 0x16, 0x16,
    0x19, 0x19, 0x1A, 0x1A, 0x1C, 0x1C, 0x1F, 0x1F,
    0x20, 0x20, 0x23, 0x23, 0x25, 0x25, 0x26, 0x26,
    0x29, 0x29, 0x2A, 0x2A, 0x2C, 0x2C, 0x2F, 0x2F,
    0x31, 0x31, 0x32, 0x32, 0x34, 0x34, 0x37, 0x37,
    0x38, 0x38, 0x3B, 0x3B, 0x3D, 0x3D, 0x3E, 0x3E,
    0x40, 0x40, 0x43, 0x43, 0x45, 0x45, 0x46, 0x46,
    0x49, 0x49, 0x4A, 0x4A, 0x4C, 0x4C, 0x4F, 0x4F,
    0x51, 0x51, 0x52, 0x52, 0x54, 0x54, 0x57, 0x57,
    0x58, 0x58, 0x5B, 0x5B, 0x5D, 0x5D, 0x5E, 0x5E,
    0x61, 0x61, 0x62, 0x62, 0x64, 0x64, 0x67, 0x67,
    0x68, 0x68, 0x6B, 0x6B, 0x6D, 0x6D, 0x6E, 0x6E,
    0x70, 0x70, 0x73, 0x73, 0x75, 0x75, 0x76, 0x76,
    0x79, 0x79, 0x7A, 0x7A, 0x7C, 0x7C, 0x7F, 0x7F,
    0x80, 0x80, 0x83, 0x83, 0x85, 0x85, 0x86, 0x86,
    0x89, 0x89, 0x8A, 0x8A, 0x8C, 0x8C, 0x8F, 0x8F,
    0x91, 0x91, 0x92, 0x92, 0x94, 0x94, 0x97, 0x97,
    0x98, 0x98, 0x9B, 0x9B, 0x9D, 0x9D, 0x9E, 0x9E,
    0xA1, 0xA1, 0xA2, 0xA2, 0xA4, 0xA4, 0xA7, 0xA7,
    0xA8, 0xA8, 0xAB, 0xAB, 0xAD, 0xAD, 0xAE, 0xAE,
    0xB0, 0xB0, 0xB3, 0xB3, 0xB5, 0xB5, 0xB6, 0xB6,
    0xB9, 0xB9, 0xBA, 0xBA, 0xBC, 0xBC, 0xBF, 0xBF,
    0xC1, 0xC1, 0xC2, 0xC2, 0xC4, 0xC4, 0xC7, 0xC7,
    0xC8, 0xC8, 0xCB, 0xCB, 0xCD, 0xCD, 0xCE, 0xCE,
    0xD0, 0xD0, 0xD3, 0xD3, 0xD5, 0xD5, 0xD6, 0xD6,
    0xD9, 0xD9, 0xDA, 0xDA, 0xDC, 0xDC, 0xDF, 0xDF,
    0xE0, 0xE0, 0xE3, 0xE3, 0xE5, 0xE5, 0xE6, 0xE6,
    0xE9, 0xE9, 0xEA, 0xEA, 0xEC, 0xEC, 0xEF, 0xEF,
    0xF1, 0xF1, 0xF2, 0xF2, 0xF4, 0xF4, 0xF7, 0xF7,
    0xF8, 0xF8, 0xFB, 0xFB, 0xFD, 0xFD, 0xFE, 0xFE
))


def des_set_odd_parity(key: bytearray):
    key[:] = (_DES_PARITYTABLE[b] for b in key)


def rotl64(x: int, c: int):
    return ((x << c) | (x >> (0x40 - c))) & 0xFFFFFFFFFFFFFFFF


def rotl32(x: int, c: int):
    return ((x << c) | (x >> (0x20 - c))) & 0xFFFFFFFF


def rotl16(x: int, c: int):
    return ((x << c) | (x >> (0x10 - c))) & 0xFFFF


def rotl08(x: int, c: int):
    return ((x << c) | (x >> (0x08 - c))) & 0xFF


def rotr64(x: int, c: int):
    return (x << (0x40 - c) & 0xFFFFFFFFFFFFFFFF) | (x >> c)


def rotr32(x: int, c: int):
    return (x << (0x20 - c) & 0xFFFFFFFF) | (x >> c)


def rotr16(x: int, c: int):
    return (x << (0x10 - c) & 0xFFFF) | (x >> c)


def rotr08(x: int, c: int):
    return (x << (0x08 - c) & 0xFF) | (x >> c)


class Direction(str, Enum):
    Encrypt = 'encrypt'
    Decrypt = 'decrypt'


class CipherMode(ABC):

    encrypt_block: Callable[[memoryview], memoryview]
    decrypt_block: Callable[[memoryview], memoryview]

    @abstractmethod
    def encrypt(self) -> Generator[memoryview, memoryview, None]:
        raise NotImplementedError

    @abstractmethod
    def decrypt(self) -> Generator[memoryview, memoryview, None]:
        raise NotImplementedError

    def apply(
        self,
        direction: Direction,
        dst: memoryview,
        src: memoryview,
        encrypt_block: Callable[[memoryview], memoryview],
        decrypt_block: Callable[[memoryview], memoryview],
        blocksize: int,
    ) -> memoryview:
        self.encrypt_block = encrypt_block
        self.decrypt_block = decrypt_block
        engine: Generator[memoryview, memoryview, None] = {
            Direction.Encrypt: self.encrypt,
            Direction.Decrypt: self.decrypt,
        }[direction]()
        next(engine)
        for k in range(0, len(src), blocksize):
            dst[k:k + blocksize] = engine.send(src[k:k + blocksize])
        engine.close()
        return dst


@_register_cipher_mode
class ECB(CipherMode):

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
    def __init__(self) -> None:
        super().__init__('Data not aligned to block size.')


class StatefulCipherMode(CipherMode):

    iv: BufferType

    def __init__(self, iv: BufferType):
        self.iv = iv


@_register_cipher_mode
class CBC(StatefulCipherMode):

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

    def __init__(self, iv: BufferType, segment_size: Optional[int] = None):
        if segment_size is None:
            segment_size = 8
        if segment_size % 8 != 0:
            raise NotImplementedError('segment sizes may only be multiples of 8')
        segment_size = segment_size // 8
        if len(iv) % segment_size != 0:
            raise NotImplementedError(
                F'the block size {len(iv)*8} is not an even multiple of the segment '
                F'size {segment_size*8}; this is currently not supported.')
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

    counter_len: int
    prefix: BufferType
    suffix: BufferType
    initial_value: int
    little_endian: bool
    block_size: int

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
        mask = (1 << (self.counter_len * 8)) - 1
        while True:
            M = yield C
            S[J] = K.to_bytes(self.counter_len, self.byte_order)
            K = K + 1 & mask
            C = strxor(E(S), M)

    decrypt = encrypt


class CipherInterface(ABC):
    @abstractmethod
    def encrypt(self, M: BufferType) -> BufferType: ...
    @abstractmethod
    def decrypt(self, C: BufferType) -> BufferType: ...


class CipherObjectFactory(ABC):
    key_size: int
    block_size: int
    name: str

    @abstractmethod
    def new(
        self,
        key: BufferType,
        iv: Optional[BufferType] = None,
        counter: Optional[int] = None,
        initial_value: Optional[int] = 0,
        nonce: Optional[BufferType] = None,
        mode: Optional[str] = None,
        segment_size: Optional[int] = None
    ) -> CipherInterface:
        ...


class BlockCipherFactory(CipherObjectFactory):
    cipher: Type[BlockCipher]

    def __init__(self, cipher: Type[BlockCipher]):
        self.cipher = cipher
        self._modes = []
        for name, mode in CIPHER_MODES.items():
            setattr(self, F'MODE_{name}', len(self._modes))
            self._modes.append(mode)

    def new(self, key, mode=None, **mode_args) -> CipherInterface:
        if mode is not None:
            mode = self._modes[mode]
        if mode is CTR:
            mode_args.update(block_size=self.cipher.block_size)
        mode = mode(**mode_args)
        return self.cipher(key, mode)

    @property
    def block_size(self):
        return self.cipher.block_size

    @property
    def key_size(self):
        return self.cipher.valid_key_sizes

    @property
    def name(self):
        return self.cipher.__name__


class BlockCipher(CipherInterface, ABC):
    block_size: int
    key: BufferType
    mode: CipherMode
    valid_key_sizes: Container[int]

    def __init__(self, key: BufferType, mode: Optional[CipherMode]):
        if len(key) not in self.valid_key_sizes:
            raise ValueError(F'The key size {len(key)} is not supported by {self.__class__.__name__.lower()}.')
        self.key = key
        self.mode = mode or ECB()

    @abstractmethod
    def block_encrypt(self, data: BufferType) -> BufferType:
        raise NotImplementedError

    @abstractmethod
    def block_decrypt(self, data: BufferType) -> BufferType:
        raise NotImplementedError

    def _apply_blockwise(self, direction: Direction, data: BufferType) -> BufferType:
        block_size = self.block_size
        mode = self.mode
        if len(data) % block_size != 0:
            raise DataUnaligned
        dst = src = memoryview(data)
        if dst.readonly:
            dst = bytearray(src)
        return mode.apply(
            direction,
            dst,
            src,
            self.block_encrypt,
            self.block_decrypt,
            block_size
        )

    def encrypt(self, data: BufferType) -> BufferType:
        return self._apply_blockwise(Direction.Encrypt, data)

    def decrypt(self, data: BufferType) -> BufferType:
        return self._apply_blockwise(Direction.Decrypt, data)
