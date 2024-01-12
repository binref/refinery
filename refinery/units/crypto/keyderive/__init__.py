#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Implements key derivation routines. These are mostly meant to be used as
modifiers for multibin expressions that can be passed as key arguments to
modules in `refinery.units.crypto.cipher`.
"""
from __future__ import annotations

import importlib

from refinery.units import Arg, Unit
from refinery.lib.argformats import number
from refinery.lib.types import ByteStr

from enum import Enum
from typing import Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Protocol

    class _Hash(Protocol):
        def update(self, data: ByteStr): ...
        def digest(self) -> ByteStr: ...
        def hexdigest(self) -> str: ...

    class _HashModule(Protocol):
        def new(self, data=None) -> _Hash: ...


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


def multidecode(data: ByteStr, function: Callable[[str], ByteStr]) -> ByteStr:
    for codec in ['utf8', 'latin1', 'cp1252']:
        try:
            return function(data.decode(codec))
        except UnicodeError:
            continue
    else:
        return function(''.join(chr(t) for t in data))


class KeyDerivation(Unit, abstract=True):

    def __init__(
        self,
        size: Arg(help='The number of bytes to generate.', type=number),
        salt: Arg(help='Salt for the derivation.'),
        hash: Arg.Option(choices=HASH, metavar='hash',
            help='Specify one of these algorithms (default is {default}): {choices}') = None,
        iter: Arg.Number(metavar='iter', help='Number of iterations; default is {default}.') = None,
        **kw
    ):
        if hash is not None:
            hash = Arg.AsOption(hash, HASH)
        return super().__init__(salt=salt, size=size, iter=iter, hash=hash, **kw)

    @property
    def hash(self) -> _HashModule:
        name = self.args.hash.value
        hash = importlib.import_module(F'Cryptodome.Hash.{name}')
        return hash
