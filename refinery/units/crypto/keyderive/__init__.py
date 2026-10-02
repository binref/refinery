"""
Implements key derivation routines. These are mostly meant to be used as
modifiers for multibin expressions that can be passed as key arguments to
modules in `refinery.units.crypto.cipher`.
"""
from __future__ import annotations

import abc
import importlib

from enum import Enum
from itertools import islice
from typing import TYPE_CHECKING, Iterable, cast

from refinery.lib.types import Param, asbuffer, buf
from refinery.units import Arg, Unit, RefineryPartialResult

if TYPE_CHECKING:
    from typing import Protocol

    class _Hash(Protocol):
        def update(self, data: buf):
            ...

        def digest(self) -> bytes:
            ...

        def hexdigest(self) -> str:
            ...

        @property
        def digest_size(self) -> int:
            ...

    class _HashModule(Protocol):
        def new(self, data=None) -> _Hash:
            ...

        @property
        def digest_size(self) -> int:
            ...


__all__ = ['Arg', 'HASH', 'KeyDerivation']


class HASH(str, Enum):
    MD2 = 'MD2'
    MD4 = 'MD4'
    MD5 = 'MD5'
    SHA1 = 'SHA'
    SHA256 = 'SHA256'
    SHA512 = 'SHA512'
    SHA224 = 'SHA224'
    SHA384 = 'SHA384'


class KeyDerivation(Unit, abstract=True):

    def __init__(
        self,
        size: Param[int, Arg.Number(help='The number of bytes to generate.')],
        salt: Param[buf, Arg.Binary(help='Salt for the derivation.')],
        hash: Param[str, Arg.Option(choices=HASH, metavar='hash',
            help='Specify one of these algorithms (default is {default}): {choices}')] = HASH.SHA1,
        iter: Param[int, Arg.Number(metavar='iter',
            help='Number of iterations; default is {default}.')] = 0,
        **kw
    ):
        if hash is not None:
            hash = Arg.AsOption(hash, HASH)
        return super().__init__(salt=salt, size=size, iter=iter, hash=hash, **kw)

    @abc.abstractmethod
    def keystream(self, seed: buf) -> Iterable[int]:
        pass

    def _hash_interface(self) -> _HashModule:
        return cast('_HashModule', self._hash_module())

    def _hash_module(self):
        name = self.args.hash.value
        return importlib.import_module(F'Cryptodome.Hash.{name}')

    def process(self, data):
        ks = self.keystream(data)
        nb = self.args.size
        if not (buf := asbuffer(ks)):
            buf = bytearray(islice(ks, 0, nb))
        if (n := len(buf)) < nb:
            raise RefineryPartialResult(
                F'Requested {nb} bytes, but given {self.args.hash!s}, '
                F'{self.name} can only produce {n} bytes.', buf)
        return buf[:nb]
