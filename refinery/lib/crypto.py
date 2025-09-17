"""
Primitives used in custom cryptographic implementations.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import Callable, ClassVar, Collection, Generator

from refinery.lib.types import buf as BufferType

CIPHER_MODES: dict[str, type[CipherMode]] = {}


def strxor(a: bytes, b: bytes):
    """
    Return the XOR of the two byte strings `a` and `b`. The shorter of the two strings defines the
    length of the output.
    """
    return bytes(a ^ b for a, b in zip(a, b))


def _register_cipher_mode(cls: type[CipherMode]):
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


def pad_pkcs7(data: bytearray, block_size: int) -> None:
    """
    Pad a bytearray in-place using the PKCS7 padding type.
    """
    for _ in range(p := block_size - len(data) % block_size):
        data.append(p)


def pad_x923(data: bytearray, block_size: int) -> None:
    """
    Pad a bytearray in-place using the ANSI x923 padding type.
    """
    p = block_size - len(data) % block_size
    data.extend(0 for _ in range(p - 1))
    data.append(p)


def pad_iso7816(data: bytearray, block_size: int) -> None:
    """
    Pad a bytearray in-place using the ISO-7816 padding type.
    """
    data.append(0x80)
    for _ in range(-len(data) % block_size):
        data.append(0)


def unpad_pkcs7(data: bytearray, block_size: int) -> None:
    """
    Remove a PKCS7 padding in-place. When an exception occurs, the data is left unchanged.
    """
    if not 1 <= (p := data[-1]) <= block_size:
        raise ValueError
    if not all(data[-k] == p for k in range(1, p + 1)):
        raise ValueError
    del data[-p:]


def unpad_x923(data: bytearray, block_size: int) -> None:
    """
    Remove an ANSI x923 padding in-place. When an exception occurs, the data is left unchanged.
    """
    if not 1 <= (p := data[-1]) <= block_size:
        raise ValueError
    for k in range(2, p + 1):
        if data[-k]:
            raise ValueError
    del data[-p:]


def unpad_iso7816(data: bytearray, block_size: int) -> None:
    """
    Remove an ISO-7816 padding in-place. When an exception occurs, the data is left unchanged.
    """
    for k in range(1, block_size + 1):
        b = data[-k]
        if b == 0x80:
            del data[-k:]
            return
        if b != 0x00:
            raise ValueError


class Padding(str, Enum):
    """
    Supported padding methods for `refinery.lib.crypto.unpad` and `refinery.lib.crypto.pad`.
    """
    PKCS7 = 'pkcs7'
    ISO7816 = 'iso7816'
    X923 = 'x923'


def unpad(data: bytearray, block_size: int, method: str | Padding):
    """
    Remove padding from the given buffer in place for the given block size according to the given
    padding method.
    """
    if method == Padding.PKCS7:
        return unpad_pkcs7(data, block_size)
    if method == Padding.X923:
        return unpad_x923(data, block_size)
    if method == Padding.ISO7816:
        return unpad_iso7816(data, block_size)
    raise ValueError(method)


def pad(data: bytearray, block_size: int, method: str | Padding):
    """
    Pad the given buffer in place to the given block size according to the given padding method.
    """
    if method == Padding.PKCS7:
        return pad_pkcs7(data, block_size)
    if method == Padding.X923:
        return pad_x923(data, block_size)
    if method == Padding.ISO7816:
        return pad_iso7816(data, block_size)
    raise ValueError(method)


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

    encrypt_block: Callable[[BufferType], BufferType]
    decrypt_block: Callable[[BufferType], BufferType]
    aligned: bool = True
    _identifier: ClassVar[int]

    @abstractmethod
    def encrypt(self) -> Generator[BufferType, memoryview, None]:
        """
        Implements data encryption according to the current cipher mode and underlying cipher.
        """
        raise NotImplementedError

    @abstractmethod
    def decrypt(self) -> Generator[BufferType, memoryview, None]:
        """
        Implements data decryption according to the current cipher mode and underlying cipher.
        """
        raise NotImplementedError

    def apply(
        self,
        operation: Operation,
        dst: memoryview,
        src: memoryview,
        encrypt_block: Callable[[BufferType], BufferType],
        decrypt_block: Callable[[BufferType], BufferType],
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
        engine: Generator[BufferType, memoryview, None] = {
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

    def decrypt(self) -> Generator[BufferType, memoryview, None]:
        M = B''
        D = self.decrypt_block
        while True:
            C = yield M
            M = D(C)

    def encrypt(self) -> Generator[BufferType, memoryview, None]:
        C = B''
        E = self.encrypt_block
        while True:
            M = yield C
            C = E(M)


class DataUnaligned(ValueError):
    """
    Raised when input data is unexpectedly unaligned to the current block size.
    """
    def __init__(self, b: int, k: int) -> None:
        super().__init__(F'Data not aligned to block size {b}, with {k} missing bytes to complete the block.')


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

    def encrypt(self) -> Generator[BufferType, memoryview, None]:
        C = self.iv
        E = self.encrypt_block
        while True:
            M = yield C
            C = E(strxor(M, C))

    def decrypt(self) -> Generator[BufferType, memoryview, None]:
        S = self.iv
        M = B''
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

    def encrypt(self) -> Generator[BufferType, memoryview, None]:
        S = self.iv
        C = B''
        E = self.encrypt_block
        while True:
            M = yield C
            C = E(strxor(M, S))
            S = strxor(C, M)

    def decrypt(self) -> Generator[BufferType, memoryview, None]:
        S = self.iv
        M = B''
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

    def __init__(self, iv: BufferType, segment_size: int | None = None):
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

    def encrypt(self) -> Generator[BufferType, memoryview, None]:
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

    def decrypt(self) -> Generator[BufferType, memoryview, None]:
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

    def encrypt(self) -> Generator[BufferType, memoryview, None]:
        S = self.iv
        C = B''
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
        block_size: int | None = None,
        counter: dict | None = None,
        nonce: BufferType | None = None,
        initial_value: int | None = 0,
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

        self.initial_value = initial_value or 0
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

    def encrypt(self) -> Generator[BufferType, memoryview, None]:
        S = bytearray(self.block_size)
        J = slice(len(self.prefix), self.block_size - len(self.suffix))
        K = self.initial_value
        if self.prefix:
            S[:+len(self.prefix)] = self.prefix
        if self.suffix:
            S[-len(self.suffix):] = self.suffix
        C = B''
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

    key_size: Collection[int]
    """
    A sequence containing all valid key sizes for this cipher.
    """

    block_size: int
    """
    The block size of this cipher.
    """

    @abstractmethod
    def encrypt(self, data: BufferType) -> BufferType:
        """
        Data encryption according to this cipher interface.
        """

    @abstractmethod
    def decrypt(self, data: BufferType) -> BufferType:
        """
        Data decryption according to this cipher interface.
        """

    def update(self, D: BufferType) -> None:
        """
        Provide additional authenticated data to a cipher that supports authentication. This method
        must be called before decryption.
        """
        return

    def verify(self, T: BufferType) -> bool:
        """
        Verify that the decrypted message is authentic given the input tag.
        """
        raise NotImplementedError

    def digest(self) -> BufferType:
        """
        Compute the binary authentication tag (MAC).
        """
        raise NotImplementedError


class CipherObjectFactory(ABC):
    """
    An abstract class to build `refinery.lib.crypto.CipherInterface`s from an asortment of
    cryptographic secrets and parameters.
    """

    name: str
    key_size: Collection[int] | None = None
    block_size: int | None = None

    @abstractmethod
    def new(
        self,
        key: BufferType,
        *,
        iv: BufferType | None = None,
        counter: int | None = None,
        initial_value: int | None = 0,
        nonce: BufferType | None = None,
        mode: str | None = None,
        segment_size: int | None = None,
        block_size: int | None = None,
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

    cipher: type[BlockCipher]

    def __init__(self, cipher: type[BlockCipher]):
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
                block_size = cipher(key, ECB(), **args).block_size
            mode_arguments.update(block_size=block_size)
        if mode is None:
            mode = ECB
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
    key_size: Collection[int]

    def __init__(self, key: BufferType, mode: CipherMode | None):
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
        if (k := -len(data) % block_size) and mode.aligned:
            raise DataUnaligned(block_size, k)
        dst = src = memoryview(data)
        if dst.readonly:
            dst = memoryview(bytearray(src))
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
