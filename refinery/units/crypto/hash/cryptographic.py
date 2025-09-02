#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Implements various cryptographic hashing algorithms.
"""
from __future__ import annotations

import hashlib

from refinery.units import Executable
from refinery.units.crypto.hash import HashUnit
from refinery.lib.tools import normalize_to_display


def _docstr(name: str):
    return F'Returns the {normalize_to_display(name.upper())} hash of the input data.'


class _CDome(Executable):
    def __new__(cls, _: str, bases, namespace: dict, kernel: str):
        def _algorithm(self, data):
            return getattr(__import__(F'Cryptodome.Hash.{algo}').Hash, algo).new(data).digest()
        algo = kernel.upper()
        namespace['_algorithm'] = _algorithm
        namespace['__doc__'] = _docstr(kernel)
        return Executable.__new__(cls, kernel, bases, namespace)

    def __init__(cls, name, bases, nmspc, kernel: str, **kw):
        super().__init__(name, bases, nmspc, **kw)


class _PyLib(Executable):
    def __new__(cls, _: str, bases, namespace: dict, kernel: str):
        def _algorithm(self, data):
            return getattr(hashlib, kernel)(data).digest()
        namespace['_algorithm'] = _algorithm
        namespace['__doc__'] = _docstr(kernel)
        return Executable.__new__(cls, kernel, bases, namespace)

    def __init__(cls, name, bases, nmspc, kernel: str, **kw):
        super().__init__(name, bases, nmspc, **kw)


__globs = globals()
__all__ = [
    'ripemd128',
    'md2',
    'md4',
    'ripemd160',
    'keccak256',
    'md5',
    'sha1',
    'sha224',
    'sha256',
    'sha384',
    'sha512',
    'blk224',
    'blk256',
    'blk384',
    'blk512',
    'sha3_224',
    'sha3_256',
    'sha3_384',
    'sha3_512',
]

for h in __all__[1:5]:
    class __cd_hash(HashUnit, metaclass=_CDome, kernel=h):
        ...
    __globs[h] = __cd_hash

for h in __all__[5:]:
    class __py_hash(HashUnit, metaclass=_PyLib, kernel=h):
        ...
    __globs[h] = __py_hash


class ripemd128(HashUnit):
    """
    Returns the RIPEMD-128 hash of the input data.
    """
    def _algorithm(self, data):
        from refinery.lib.ripemd128 import ripemd128
        return ripemd128(data)
