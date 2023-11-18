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
    Sequence,
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
    Arg,
    Executable,
    RefineryCriticalException,
    RefineryPartialResult,
    Unit,
)


class CipherUnit(Unit, abstract=True):

    key_size: Optional[Sequence[int]] = None
    block_size: int

    def __init__(self, key: Arg(help='The encryption key.'), **keywords):
        super().__init__(key=key, **keywords)

    @abc.abstractmethod
    def decrypt(self, data: ByteString) -> ByteString:
        raise NotImplementedError

    @abc.abstractmethod
    def encrypt(self, data: ByteString) -> ByteString:
        raise NotImplementedError

    def process(self, data: ByteString) -> ByteString:
        if self.key_size and len(self.args.key) not in self.key_size:
            import itertools
            key_size_iter = iter(self.key_size)
            key_size_options = [str(k) for k in itertools.islice(key_size_iter, 0, 5)]
            try:
                next(key_size_iter)
            except StopIteration:
                pt = '.'
            else:
                pt = ', ...'
            if len(key_size_options) == 1:
                msg = F'{self.name} requires a key size of {key_size_options[0]}'
            else:
                msg = R', '.join(key_size_options)
                msg = F'possible key sizes for {self.name} are: {msg}'
            raise ValueError(F'the given key has an invalid length of {len(self.args.key)} bytes; {msg}{pt}')
        return self.decrypt(data)

    def reverse(self, data: ByteString) -> ByteString:
        return self.encrypt(data)


class StreamCipherUnit(CipherUnit, abstract=True):

    block_size = 1

    def __init__(
        self, key,
        discard: Arg.Number('-d', help='Discard the first {varname} bytes of the keystream, {default} by default.') = 0,
        stateful: Arg.Switch('-s', help='Do not reset the key stream while processing the chunks of one frame.') = False,
        **keywords
    ):
        super().__init__(key=key, stateful=stateful, discard=discard, **keywords)
        self._keystream = None

    @abc.abstractmethod
    def keystream(self) -> Iterable[int]:
        raise NotImplementedError

    @Unit.Requires('numpy', 'speed', 'default', 'extended')
    def _numpy():
        import numpy
        return numpy

    def encrypt(self, data: bytearray) -> bytearray:
        it = self._keystream or self.keystream()
        for _ in range(self.args.discard):
            next(it)
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


PADDINGS_LIB = ['pkcs7', 'iso7816', 'x923']
PADDING_NONE = 'raw'
PADDINGS_ALL = PADDINGS_LIB + [PADDING_NONE]


class BlockCipherUnitBase(CipherUnit, abstract=True):
    def __init__(
        self, key, iv: Arg('-i', '--iv', help=(
            'Specifies the initialization vector. If none is specified, then a block of zero bytes is used.')) = None,
        padding: Arg.Choice('-p', type=str.lower, choices=PADDINGS_ALL, metavar='P', help=(
            'Choose a padding algorithm ({choices}). The raw algorithm does nothing. By default, all other algorithms '
            'are attempted. In most cases, the data was not correctly decrypted if none of these work.')
        ) = None,
        raw: Arg.Switch('-r', '--raw', help='Set the padding to raw; ignored when a padding is specified.') = False,
        **keywords
    ):
        if not padding and raw:
            padding = PADDING_NONE
        super().__init__(key=key, iv=iv, padding=padding, **keywords)

    @property
    @abc.abstractmethod
    def block_size(self) -> int:
        raise NotImplementedError

    @property
    def iv(self) -> ByteString:
        return self.args.iv or bytes(self.block_size)

    def _default_padding(self) -> Optional[str]:
        return self.args.padding

    def reverse(self, data: ByteString) -> ByteString:
        padding = self._default_padding()
        if padding is not None:
            self.log_info('padding method:', padding)
            if padding in PADDINGS_LIB:
                from Cryptodome.Util.Padding import pad
                data = pad(data, self.block_size, padding)
        return super().reverse(data)

    def process(self, data: ByteString) -> ByteString:
        padding = self._default_padding()
        result = super().process(data)
        if padding is None:
            return result

        from Cryptodome.Util.Padding import unpad
        padding = [padding, *(p for p in PADDINGS_LIB if p != padding)]

        for p in padding:
            if p == PADDING_NONE:
                return result
            try:
                unpadded = unpad(result, self.block_size, p.lower())
            except Exception:
                pass
            else:
                self.log_info(F'unpadding worked using {p}')
                return unpadded
        raise RefineryPartialResult(
            'None of these paddings worked: {}'.format(', '.join(padding)),
            partial=result)


class StandardCipherExecutable(Executable):

    _available_block_cipher_modes: ClassVar[Type[Option]]
    _cipher_factory: ClassVar[Optional[CipherObjectFactory]]

    def __new__(mcs, name, bases, nmspc, cipher: Optional[CipherObjectFactory] = None):
        keywords = dict(abstract=(cipher is None))
        return super(StandardCipherExecutable, mcs).__new__(mcs, name, bases, nmspc, **keywords)

    def __init__(_class, name, bases, nmspc, cipher: Optional[CipherObjectFactory] = None):
        abstract = cipher is None
        super(StandardCipherExecutable, _class).__init__(name, bases, nmspc, abstract=abstract)
        _class._cipher_factory = cipher
        if abstract:
            return
        b_size = cipher.block_size
        k_size = cipher.key_size
        if b_size is not None:
            _class.block_size = b_size
        else:
            b_size = getattr(_class, 'block_size', 2)
            if not isinstance(b_size, int):
                b_size = None
        if k_size is not None:
            _class.key_size = k_size
        if b_size and b_size <= 1:
            return
        if 'mode' not in _class._argument_specification:
            return
        modes = extract_options(cipher, 'MODE_', 'SIV', 'OPENPGP')
        check = set(modes)
        if not modes:
            raise RefineryCriticalException(F'No cipher block mode constants found in {cipher!r}')
        if not check & {'CFB'}:
            _class._argument_specification.pop('segment_size', None)
        if not check & {'EAX', 'GCM', 'OCB', 'CCM'}:
            _class._argument_specification.pop('mac_len', None)
        if not check & {'CCM'}:
            _class._argument_specification.pop('assoc_len', None)
        _class._available_block_cipher_modes = OptionFactory(modes, ignorecase=True)
        _class._argument_specification['mode'].merge_all(Arg(
            '-m', '--mode', type=str.upper, metavar='M', nargs=Arg.delete, choices=list(modes),
            help=(
                'Choose cipher mode to be used. Possible values are: {}. By default, the CBC mode'
                '  is used when an IV is is provided, and ECB otherwise.'.format(', '.join(modes))
            )
        ))


class StandardCipherUnit(CipherUnit, metaclass=StandardCipherExecutable):

    _available_block_cipher_modes: ClassVar[Type[Option]]
    _cipher_factory: ClassVar[CipherObjectFactory]
    _cipher_interface: Optional[CipherInterface] = None

    def _new_cipher(self, **optionals) -> CipherInterface:
        self.log_info(lambda: F'encryption key: {self.args.key.hex()}')
        return self._cipher_factory.new(key=self.args.key, **optionals)

    def _get_cipher(self, reset_cache=False) -> CipherInterface:
        co = self._cipher_interface
        if co is None or reset_cache:
            self._cipher_interface = co = self._new_cipher()
        return co

    @property
    def block_size(self) -> int:
        return self._get_cipher().block_size

    @property
    def key_size(self) -> Optional[Sequence[int]]:
        return self._get_cipher().key_size

    def encrypt(self, data: bytes) -> bytes:
        cipher = self._get_cipher(True)
        assert cipher.block_size == self.block_size
        return cipher.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        cipher = self._get_cipher(True)
        assert cipher.block_size == self.block_size
        try:
            return cipher.decrypt(data)
        except ValueError:
            overlap = len(data) % self.block_size
            if not overlap:
                raise
            data[-overlap:] = []
            self.log_warn(F'removing {overlap} bytes from the input to make it a multiple of the {self.block_size}-byte block size')
            return cipher.decrypt(data)


class StandardBlockCipherUnit(BlockCipherUnitBase, StandardCipherUnit):

    def __init__(
        self, key, iv=B'', *,
        padding=None, mode=None, raw=False,
        little_endian: Arg.Switch('-e', '--little-endian',
            help='Only for CTR: Use a little endian counter instead of the default big endian.') = False,
        segment_size: Arg.Number('-S', '--segment-size', help=(
            'Only for CFB: Number of bits into which data is segmented. It must be a multiple of 8. The default of {default} means '
            'that the block size will be used as the segment size.')) = 0,
        mac_len: Arg.Number('-M', '--mac-len', bound=(4, 16),
            help='Only for EAX, GCM, OCB, and CCM: Length of the authentication tag, in bytes.') = 0,
        assoc_len: Arg.Number('-A', '--assoc-len',
            help='Only for CCM: Length of the associated data. If not specified, all associated data is buffered internally.') = 0,
        **keywords
    ):
        mode = self._available_block_cipher_modes(mode or iv and 'CBC' or 'ECB')
        if iv and mode.name == 'ECB':
            raise ValueError('No initialization vector can be specified for ECB mode.')
        super().__init__(
            key=key,
            iv=iv,
            padding=padding,
            mode=mode,
            raw=raw,
            segment_size=segment_size,
            mac_len=mac_len,
            assoc_len=assoc_len,
            little_endian=little_endian,
            **keywords
        )

    def _default_padding(self) -> Optional[str]:
        padding = super()._default_padding()
        if padding is not None:
            return padding
        elif self.args.mode.name in {'ECB', 'CBC', 'PCBC'}:
            return PADDINGS_LIB[0]

    @property
    def block_size(self) -> int:
        provider = StandardCipherUnit
        return provider.block_size.fget(self)

    @property
    def key_size(self) -> Sequence[int]:
        provider = StandardCipherUnit
        return provider.key_size.fget(self)

    def _new_cipher(self, **optionals) -> CipherInterface:
        mode = self.args.mode.name
        if mode != 'ECB':
            iv = bytes(self.iv)
            if mode == 'CTR':
                from Cryptodome.Util import Counter
                little_endian = self.args.little_endian
                order = 'little' if little_endian else 'big'
                counter = Counter.new(
                    self.block_size * 8,
                    initial_value=int.from_bytes(iv, order),
                    little_endian=little_endian)
                optionals['counter'] = counter
            elif mode in ('CCM', 'EAX', 'GCM', 'SIV', 'OCB', 'CTR'):
                if mode in ('CCM', 'EAX', 'GCM', 'OCB'):
                    ml = self.args.mac_len
                    if ml > 0:
                        if ml not in range(4, 17):
                            raise ValueError(F'The given mac length {ml} is not in range [4,16].')
                        optionals['mac_len'] = ml
                if mode == 'CCM':
                    al = self.args.assoc_len
                    if al > 0:
                        optionals['assoc_len'] = al
                bounds = {
                    'CCM': (7, self.block_size - 2),
                    'OCB': (1, self.block_size),
                    'CTR': (1, self.block_size),
                }.get(mode, None)
                if bounds and len(iv) not in range(*bounds):
                    raise ValueError(F'Invalid nonce length, must be in {bounds} for {mode}.')
                optionals['nonce'] = iv
            elif mode in ('PCBC', 'CBC', 'CFB', 'OFB', 'OPENPGP'):
                if mode == 'CFB':
                    sz = self.args.segment_size
                    if sz % 8 != 0:
                        raise ValueError(F'The given segment size {sz} is not a multiple of 8.')
                    if not sz:
                        sz = self.block_size * 8
                    optionals['segment_size'] = sz
                if len(iv) > self.block_size:
                    self.log_warn(F'The IV has length {len(self.args.iv)} and will be truncated to the block size {self.block_size}.')
                    iv = iv[:self.block_size]
                elif len(iv) < self.block_size:
                    raise ValueError(F'The IV has length {len(self.args.iv)} but the block size is {self.block_size}.')
                optionals['iv'] = iv
            self.log_info('initial vector:', iv.hex())
        if self.args.mode:
            optionals['mode'] = self.args.mode.value
        return super()._new_cipher(**optionals)


class LatinCipherUnit(StreamCipherUnit, abstract=True):
    key_size = {16, 32, 64}
    block_size = 1

    def __init__(
        self, key, stateful=False, discard=0,
        nonce: Arg(help='The nonce. Default is the string {default}.') = B'REFINERY',
        magic: Arg('-m', help='The magic constant; depends on the key size by default.') = B'',
        offset: Arg.Number('-x', help='Optionally specify the stream index, default is {default}.') = 0,
        rounds: Arg.Number('-r', help='The number of rounds. Has to be an even number.') = 20,
    ):
        super().__init__(
            key=key,
            nonce=nonce,
            magic=magic,
            offset=offset,
            rounds=rounds,
            stateful=stateful,
            discard=discard
        )


class LatinCipherStandardUnit(StandardCipherUnit):
    def __init__(self, key, nonce: Arg(help='The nonce. Default is the string {default}.') = B'REFINERY'):
        super().__init__(key, nonce=nonce)

    def _new_cipher(self, **optionals) -> Any:
        self.log_info('one-time nonce:', self.args.nonce.hex())
        return super()._new_cipher(nonce=self.args.nonce)
