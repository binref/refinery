#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Implements various cryptographic hashing algorithms.
"""
import hashlib

from refinery.units import Executable
from refinery.units.crypto.hash import HashUnit


class _CDome(Executable):
    def __new__(cls, name: str, bases, namespace: dict):
        def _algorithm(self, data):
            return getattr(__import__(F'Cryptodome.Hash.{algo}').Hash, algo).new(data).digest()
        algo = name.upper()
        namespace['_algorithm'] = _algorithm
        return Executable.__new__(cls, name, bases, namespace)


class _PyLib(Executable):
    def __new__(cls, name: str, bases, namespace: dict):
        def _algorithm(self, data):
            return getattr(hashlib, name)(data).digest()
        namespace['_algorithm'] = _algorithm
        return Executable.__new__(cls, name, bases, namespace)


__G = globals()
__C = {
    'md2'      : _CDome,
    'md4'      : _CDome,
    'ripemd160': _CDome,
    'keccak256': _CDome,
    'md5'      : _PyLib,
    'sha1'     : _PyLib,
    'sha224'   : _PyLib,
    'sha256'   : _PyLib,
    'sha384'   : _PyLib,
    'sha512'   : _PyLib,
    'blk224'   : _PyLib,
    'blk256'   : _PyLib,
    'blk384'   : _PyLib,
    'blk512'   : _PyLib,
    'sha3_224' : _PyLib,
    'sha3_256' : _PyLib,
    'sha3_384' : _PyLib,
    'sha3_512' : _PyLib,
}

__all__ = list(__C)

for name, HashUnitFactory in __C.items():
    __display = name.upper().replace('_', '-')
    __G[name] = HashUnitFactory(name, (HashUnit,), {
        '__module__': __name__, '__doc__': F'Returns the {__display} hash of the input data.'})


class ripemd128(HashUnit):
    """
    Returns the RIPEMD-128 hash of the input data.
    """
    def _algorithm(self, data):
        from refinery.lib.ripemd128 import ripemd128
        return ripemd128(data)
