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

    def __new__(cls, name: str, bases, namespace: dict, kernel: str = ''):
        kernel = kernel or name
        namespace.update(__doc__=_doc(kernel), _algorithm=cls._algorithm)
        exe = Executable.__new__(cls, name, bases, namespace)
        setattr(exe, '__qualname__', name)
        return exe


class _CDome(_HashExe):
    def __init__(cls, name: str, bases, nmspc: dict, kernel: str = '', **kw):
        kernel = kernel or name.upper()

        super().__init__(name, bases, nmspc, **kw)

        def _build_hash(data: buf) -> _Hash:
            hash = __import__(F'Cryptodome.Hash.{kernel}')
            for t in ('Hash', kernel, 'new'):
                hash = getattr(hash, t)
            return hash(data)

        cls._build_hash = staticmethod(_build_hash)


class _PyLib(_HashExe):
    def __init__(cls, name: str, bases, nmspc: dict, kernel: str = '', **kw):
        kernel = kernel or name
        super().__init__(name, bases, nmspc, **kw)
        cls._build_hash = getattr(hashlib, kernel)


class ripemd160 (HashUnit, metaclass=_CDome)                     : ...  # noqa
class md2       (HashUnit, metaclass=_CDome)                     : ...  # noqa
class md4       (HashUnit, metaclass=_CDome)                     : ...  # noqa
class keccak    (HashUnit, metaclass=_CDome, kernel='keccak')    : ...  # noqa
class md5       (HashUnit, metaclass=_PyLib)                     : ...  # noqa
class sha1      (HashUnit, metaclass=_PyLib)                     : ...  # noqa
class sha224    (HashUnit, metaclass=_PyLib)                     : ...  # noqa
class sha256    (HashUnit, metaclass=_PyLib)                     : ...  # noqa
class sha384    (HashUnit, metaclass=_PyLib)                     : ...  # noqa
class sha512    (HashUnit, metaclass=_PyLib)                     : ...  # noqa
class blake2b   (HashUnit, metaclass=_PyLib)                     : ...  # noqa
class blake2s   (HashUnit, metaclass=_PyLib)                     : ...  # noqa
class sha3_224  (HashUnit, metaclass=_PyLib)                     : ...  # noqa
class sha3_256  (HashUnit, metaclass=_PyLib)                     : ...  # noqa
class sha3_384  (HashUnit, metaclass=_PyLib)                     : ...  # noqa
class sha3_512  (HashUnit, metaclass=_PyLib)                     : ...  # noqa
class shake128  (HashUnit, metaclass=_PyLib, kernel='shake_128') : ...  # noqa
class shake256  (HashUnit, metaclass=_PyLib, kernel='shake_256') : ...  # noqa


class ripemd128(HashUnit):
    """
    Returns the RIPEMD-128 hash of the input data.
    """
    def _algorithm(self, data):
        from refinery.lib.crypto.ripemd128 import ripemd128
        return ripemd128(data)
