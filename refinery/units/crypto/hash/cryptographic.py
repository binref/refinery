#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Implements various cryptographic hashing algorithms.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Callable

import hashlib

from refinery.units import Executable
from refinery.units.crypto.hash import HashUnit
from refinery.lib.tools import normalize_to_display

if TYPE_CHECKING:
    from refinery.lib.types import ByteStr
    from refinery.units.crypto.keyderive import _Hash


def _doc(name: str):
    return F'Returns the {normalize_to_display(name.upper())} hash of the input data.'


class _HashExe(Executable):
    _build_hash: Callable[[ByteStr], _Hash]

    def _algorithm(cls, data: ByteStr):
        return cls._build_hash(data).digest()

    def __new__(cls, _: str, bases, namespace: dict, export: str = '', kernel: str = ''):
        namespace.update(__doc__=_doc(kernel), _algorithm=cls._algorithm)
        exe = Executable.__new__(cls, export, bases, namespace)
        setattr(exe, '__qualname__', export)
        return exe


class _CDome(_HashExe):
    def __init__(cls, _, bases, nmspc: dict, export: str = '', kernel: str = '', **kw):
        super().__init__(export, bases, nmspc, **kw)
        hash = __import__(F'Cryptodome.Hash.{kernel}')
        for t in ('Hash', kernel, 'new'):
            hash = getattr(hash, t)
        cls._build_hash = hash


class _PyLib(_HashExe):
    def __init__(cls, _, bases, nmspc: dict, export: str = '', kernel: str = '', **kw):
        super().__init__(export, bases, nmspc, **kw)
        cls._build_hash = getattr(hashlib, kernel)

__all__ = [
    'ripemd128',
    'ripemd160',
    'md2',
    'md4',
    'keccak',
    'md5',
    'sha1',
    'sha224',
    'sha256',
    'sha384',
    'sha512',
    'blake2b',
    'blake2s',
    'sha3_224',
    'sha3_256',
    'sha3_384',
    'sha3_512',
    'shake128',
    'shake256',
]

_K = {
    'ripemd128': 'RIPEMD128',
    'ripemd160': 'RIPEMD160',
    'md2': 'MD2',
    'md4': 'MD4',
    'shake128': 'shake_128',
    'shake256': 'shake_256',
}

_G = globals()


for h in __all__[1:5]:
    class __cd_hash(HashUnit, metaclass=_CDome, export=h, kernel=_K.get(h, h)):
        ...
    _G[h] = __cd_hash

for h in __all__[5:]:
    class __py_hash(HashUnit, metaclass=_PyLib, export=h, kernel=_K.get(h, h)):
        ...
    _G[h] = __py_hash


class ripemd128(HashUnit):
    """
    Returns the RIPEMD-128 hash of the input data.
    """
    def _algorithm(self, data):
        from refinery.lib.ripemd128 import ripemd128
        return ripemd128(data)
