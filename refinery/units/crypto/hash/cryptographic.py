"""
Implements various cryptographic hashing algorithms.
"""
from __future__ import annotations

import hashlib

from typing import TYPE_CHECKING, Callable

from refinery.lib.tools import normalize_to_display
from refinery.units import Executable
from refinery.units.crypto.hash import HashUnit

if TYPE_CHECKING:
    from refinery.lib.types import buf
    from refinery.units.crypto.keyderive import _Hash


def _doc(name: str):
    return F'Returns the {normalize_to_display(name.upper())} hash of the input data.'


class _HashExe(Executable):
    _build_hash: Callable[[buf], _Hash]

    def _algorithm(cls, data: buf):
        return cls._build_hash(data).digest()

    def __new__(cls, name: str, bases, namespace: dict, export: str = '', kernel: str = ''):
        if kernel:
            namespace.update(__doc__=_doc(kernel), _algorithm=cls._algorithm)
        export = export or name
        exe = Executable.__new__(cls, export, bases, namespace)
        setattr(exe, '__qualname__', export)
        return exe


class _CDome(_HashExe):
    def __init__(cls, _, bases, nmspc: dict, export: str = '', kernel: str = '', **kw):
        super().__init__(export, bases, nmspc, **kw)
        if kernel and export:
            hash = __import__(F'Cryptodome.Hash.{kernel}')
            for t in ('Hash', kernel, 'new'):
                hash = getattr(hash, t)
            cls._build_hash = hash


class _PyLib(_HashExe):
    def __init__(cls, _, bases, nmspc: dict, export: str = '', kernel: str = '', **kw):
        super().__init__(export, bases, nmspc, **kw)
        cls._build_hash = getattr(hashlib, kernel)


__all__ = [      # noqa
    'ripemd128', # type: ignore
    'ripemd160', # type: ignore
    'md2',       # type: ignore
    'md4',       # type: ignore
    'keccak',    # type: ignore
    'md5',       # type: ignore
    'sha1',      # type: ignore
    'sha224',    # type: ignore
    'sha256',    # type: ignore
    'sha384',    # type: ignore
    'sha512',    # type: ignore
    'blake2b',   # type: ignore
    'blake2s',   # type: ignore
    'sha3_224',  # type: ignore
    'sha3_256',  # type: ignore
    'sha3_384',  # type: ignore
    'sha3_512',  # type: ignore
    'shake128',  # type: ignore
    'shake256',  # type: ignore
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
    class H(HashUnit, metaclass=_CDome, export=h, kernel=_K.get(h, h)):
        ...
    _G[h] = H
    del H

for h in __all__[5:]:
    class H(HashUnit, metaclass=_PyLib, export=h, kernel=_K.get(h, h)):
        ...
    _G[h] = H
    del H


class ripemd128(HashUnit):
    """
    Returns the RIPEMD-128 hash of the input data.
    """
    def _algorithm(self, data):
        from refinery.lib.ripemd128 import ripemd128
        return ripemd128(data)
