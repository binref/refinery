"""
Implements several popular block and stream ciphers.
"""
from __future__ import annotations

import abc

from refinery.lib.argformats import (
    Option,
    OptionFactory,
    extract_options,
)
from refinery.lib.crypto import (
    CipherInterface,
    CipherObjectFactory,
    pad,
    unpad,
)
from refinery.lib.tools import isbuffer
from refinery.lib.types import Any, ClassVar, Collection, Iterable, Param, buf, isq
from refinery.units import (
    Arg,
    Chunk,
    Executable,
    RefineryCriticalException,
    RefineryPartialResult,
    Unit,
)


class CipherUnit(Unit, abstract=True):

    key_size: Collection[int] | None = None
    block_size: int

    def __init__(self, key: Param[buf, Arg(help='The encryption key.')], **keywords):
        super().__init__(key=key, **keywords)

    @abc.abstractmethod
    def decrypt(self, data: Chunk) -> buf:
        raise NotImplementedError

    @abc.abstractmethod
    def encrypt(self, data: Chunk) -> buf:
        raise NotImplementedError

    def process(self, data: Chunk) -> buf:
        ks = self.key_size
        if ks and len(self.args.key) not in ks:
            import itertools
            key_size_iter = iter(ks)
            key_size_options = [str(k) for k in itertools.islice(key_size_iter, 0, 5)]
            try:
                next(key_size_iter)
            except StopIteration:
                pt = '.'
            else:
                pt = ', ...'
                if isinstance(ks, range):
                    pt = F'{pt}, {ks.stop - 1}'
            if len(key_size_options) == 1:
                msg = F'{self.name} requires a key size of {key_size_options[0]}'
            else:
                msg = R', '.join(key_size_options)
                msg = F'possible key sizes for {self.name} are: {msg}'
            raise ValueError(F'the given key has an invalid length of {len(self.args.key)} bytes; {msg}{pt}')
        return self.decrypt(data)

    def reverse(self, data: Chunk) -> buf:
        return self.encrypt(data)


class StreamCipherUnit(CipherUnit, abstract=True):

    block_size = 1

    def __init__(
        self, key,
        discard: Param[int, Arg.Number('-d', help='Discard the first {varname} bytes of the keystream, {default} by default.')] = 0,
        stateful: Param[bool, Arg.Switch('-s', help='Do not reset the key stream while processing the chunks of one frame.')] = False,
        **keywords
    ):
        super().__init__(key=key, stateful=stateful, discard=discard, **keywords)
        self._keystream = None

    @abc.abstractmethod
    def keystream(self) -> Iterable[int]:
        raise NotImplementedError

    @Unit.Requires('numpy', ['speed', 'default', 'extended'])
    def _numpy():
        import numpy
        return numpy

    def encrypt(self, data: Chunk) -> bytearray:
        it = iter(self._keystream or self.keystream())
        for _ in range(self.args.discard):
            next(it)
        try:
            np = self._numpy
        except ImportError:
            self.log_info('this unit could perform faster if numpy was installed.')
            data[:] = (a ^ b for a, b in zip(it, data))
        else:
            key = np.fromiter(it, dtype=np.uint8, count=len(data))
            tmp = np.frombuffer(
                memoryview(data), dtype=np.uint8, count=len(data))
            tmp ^= key
            data[:] = iter(tmp)
        return data

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
        self, key,
        iv: Param[buf, Arg('-i', '--iv', help=(
            'Specifies the initialization vector. If none is specified, then a block of zero bytes '
            'is used.')
        )] = B'',
        padding: Param[str | None, Arg.Choice('-p', choices=PADDINGS_ALL, metavar='P', help=(
            'Choose a padding algorithm ({choices}). The raw algorithm does nothing. By default, '
            'all other algorithms are attempted. In most cases, the data was not correctly '
            'decrypted if none of these work.')
        )] = None,
        raw: Param[bool, Arg.Switch('-r', '--raw', help=(
            'Set the padding to raw; ignored when a padding is specified.')
        )] = False,
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
    def iv(self) -> buf:
        return self.args.iv or bytes(self.block_size)

    def _default_padding(self) -> str | None:
        return self.args.padding

    def reverse(self, data: Chunk) -> buf:
        padding = self._default_padding()
        if padding is not None:
            self.log_info('padding method:', padding)
            if padding in PADDINGS_LIB:
                pad(data, self.block_size, padding)
        return super().reverse(data)

    def process(self, data: Chunk) -> buf:
        padding = self._default_padding()
        result = self.labelled(super().process(data))
        if padding is None:
            return result
        padding = [padding, *(p for p in PADDINGS_LIB if p != padding)]

        for p in padding:
            if p == PADDING_NONE:
                return result
            try:
                unpad(result, self.block_size, p.lower())
            except ValueError:
                continue
            else:
                self.log_info(F'unpadding worked using {p}')
                return result
        raise RefineryPartialResult(
            'None of these paddings worked: {}'.format(', '.join(padding)),
            partial=result)


class StandardCipherExecutable(Executable):

    _available_block_cipher_modes: type[Option]
    _cipher_factory: CipherObjectFactory | None

    def __new__(mcs, name, bases, nmspc, cipher: CipherObjectFactory | None = None):
        keywords: dict = dict(abstract=(cipher is None))
        return super().__new__(mcs, name, bases, nmspc, **keywords)

    def __init__(_class, name, bases, nmspc, cipher: CipherObjectFactory | None = None):
        abstract = cipher is None
        super().__init__(name, bases, nmspc, abstract=abstract)
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
            _class._argument_specification.pop('tag', None)
            _class._argument_specification.pop('aad', None)
        _class._available_block_cipher_modes = OptionFactory(modes, ignorecase=True)
        _class._argument_specification['mode'].merge_all(Arg(
            '-m', '--mode', type=str.upper, metavar='M', nargs=Arg.delete, choices=list(modes),
            help=(
                'Choose cipher mode to be used. Possible values are: {}. By default, the CBC mode'
                '  is used when an IV is is provided, and ECB otherwise.'.format(', '.join(modes))
            )
        ))


class StandardCipherUnit(CipherUnit, metaclass=StandardCipherExecutable):

    _available_block_cipher_modes: ClassVar[type[Option]]
    _cipher_factory: ClassVar[CipherObjectFactory]
    _cipher_interface: CipherInterface | None = None

    def _new_cipher(self, **optionals) -> CipherInterface:
        self.log_info(lambda: F'encryption key: {self.args.key.hex()}')
        if cf := self._cipher_factory:
            return cf.new(key=self.args.key, **optionals)
        raise RuntimeError('The cipher factory for this unit was uninitialized.')

    def _get_cipher(self, reset_cache=False) -> CipherInterface:
        if reset_cache or (ci := self._cipher_interface) is None:
            self._cipher_interface = ci = self._new_cipher()
        return ci

    @property
    def block_size(self) -> int:
        return self._get_cipher().block_size

    @property
    def key_size(self) -> Collection[int] | None:
        return self._get_cipher().key_size

    def encrypt(self, data: Chunk) -> buf:
        cipher = self._get_cipher(True)
        assert cipher.block_size == self.block_size
        return cipher.encrypt(data)

    def decrypt(self, data: Chunk) -> buf:
        try:
            return self._get_cipher(True).decrypt(data)
        except ValueError:
            overlap = len(data) % self.block_size
            if not overlap:
                raise
            del data[-overlap:]
            self.log_warn(F'removing {overlap} bytes from the input to make it a multiple of the {self.block_size}-byte block size')
            return self._get_cipher(True).decrypt(data)


class StandardBlockCipherUnit(BlockCipherUnitBase, StandardCipherUnit):

    def __init__(
        self, key, *,
        iv=B'',
        padding=None, mode=None, raw=False,
        little_endian: Param[bool, Arg.Switch('-e', '--little-endian', help=(
            'Only for CTR: Use a little endian counter instead of the default big endian.'
        ))] = False,
        segment_size: Param[int, Arg.Number('-S', '--segment-size', help=(
            'Only for CFB: Number of segmentation bits. It must be a multiple of 8. The default '
            'of {default} means that the block size will be used as the segment size.'
        ))] = 0,
        tag: Param[isq, Arg.NumSeq('-t', '--tag', metavar='TAG', help=(
            'Only for EAX, GCM, OCB, and CCM: An authentication tag to verify the message. For '
            'encryption, this parameter specifies the tag length, and the tag is provided as a '
            'meta variable named "tag".'
        ))] = (),
        aad: Param[buf, Arg.Binary('-a', '--aad', metavar='AAD', help=(
            'Only for EAX, GCM, OCB, and CCM: Set additional authenticated data.'
        ))] = B'',
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
            aad=aad,
            tag=tag,
            little_endian=little_endian,
            **keywords
        )

    def _default_padding(self) -> str | None:
        padding = super()._default_padding()
        if padding is not None:
            return padding
        elif self.args.mode.name in {'ECB', 'CBC', 'PCBC'}:
            return PADDINGS_LIB[0]

    def _get_cipher(self, reset_cache=False):
        reset_cache = reset_cache or self._cipher_interface is None
        cipher = super()._get_cipher(reset_cache)
        if reset_cache and (aad := self.args.aad):
            cipher.update(aad)
        return cipher

    def encrypt(self, data):
        result = super().encrypt(data)
        cipher = super()._get_cipher(False)
        if self.args.tag or self.args.aad:
            result = self.labelled(result, tag=cipher.digest())
        return result

    def decrypt(self, data):
        result = super().decrypt(data)
        if tag := self.args.tag:
            if not isbuffer(tag):
                raise ValueError('The tag must be a binary string during decryption.')
            cipher = super()._get_cipher(False)
            cipher.verify(tag)
        return result

    @property
    def block_size(self) -> int:
        return self._get_cipher().block_size

    @property
    def key_size(self) -> Collection[int] | None:
        return self._get_cipher().key_size

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
                if mode in ('CCM', 'EAX', 'GCM', 'OCB') and self.args.reverse and (tag := self.args.tag):
                    if not isinstance(tag, int) or tag not in range(4, 17):
                        raise ValueError('For encryption, the tag paramter must be an integer in range [4,16].')
                    optionals['mac_len'] = tag
                if mode == 'CCM':
                    if aad := self.args.aad:
                        optionals['assoc_len'] = len(aad)
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
        nonce: Param[buf, Arg(help='The nonce. Default is the string {default}.')] = B'REFINERY',
        magic: Param[buf, Arg('-m', help='The magic constant; depends on the key size by default.')] = B'',
        offset: Param[int, Arg.Number('-x', help='Optionally specify the stream index, default is {default}.')] = 0,
        rounds: Param[int, Arg.Number('-r', help='The number of rounds. Has to be an even number. Default is {default}.')] = 20,
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
    def __init__(self, key, nonce: Param[buf, Arg(help='The nonce. Default is the string {default}.')] = B'REFINERY'):
        super().__init__(key, nonce=nonce)

    def _new_cipher(self, **optionals) -> Any:
        self.log_info('one-time nonce:', self.args.nonce.hex())
        return super()._new_cipher(nonce=self.args.nonce)
