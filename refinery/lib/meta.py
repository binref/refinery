#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
File type related functions.
"""
import abc
import hashlib
from io import StringIO
import string
import zlib

from typing import Callable, Dict, Optional, ByteString, Union

from .tools import isbuffer, entropy, index_of_coincidence
from .mime import get_cached_file_magic_info
from .argformats import ParserError, PythonExpression


class CustomStringRepresentation(abc.ABC):
    @abc.abstractmethod
    def __str__(self): ...


class ByteStringWrapper:
    def __init__(self, string: ByteString, codec: str):
        self.string = string
        self.codec = codec

    def __getattr__(self, key):
        return getattr(self.string, key)

    def __repr__(self):
        return self.string.hex().upper()

    def __str__(self):
        try:
            return self.string.decode(self.codec)
        except UnicodeDecodeError:
            return self.string.decode('ascii', 'backslashreplace')

    def __format__(self, spec):
        return F'{self!s:{spec}}'


class SizeInt(int, CustomStringRepresentation):
    """
    The string representation of this int class is a a human-readable expression of size,
     using common units such as kB and MB.
    """
    width = 9

    def _s(self, align):
        step = 1000.0
        unit = None
        result = self
        for unit in [None, 'kB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB']:
            if unit and result / step <= 0.1:
                break
            result /= step
        if unit is None:
            width = 3 if align else ''
            return F'{result:{width}} BYTES'
        else:
            width = 6 if align else ''
            return F'{result:{width}.3f} {unit}'

    def __repr__(self):
        return self._s(True)

    def __str__(self):
        return self._s(False)


class Percentage(float, CustomStringRepresentation):
    def __str__(self):
        return F'{self*100:.2f}%' if 0 <= self <= 1 else F'{self:.4f}'


class GhostField:

    def __init__(self, key):
        self.key = key

    def __format__(self, spec):
        spec = spec and F':{spec}'
        return F'{{{self.key}{spec}}}'


COMMON_PROPERTIES: Dict[str, Callable[[ByteString], Union[str, int, float]]] = {
    'mime'    : lambda chunk: get_cached_file_magic_info(chunk).mime,
    'ext'     : lambda chunk: get_cached_file_magic_info(chunk).extension,
    'magic'   : lambda chunk: get_cached_file_magic_info(chunk).description,
    'size'    : lambda chunk: SizeInt(len(chunk)),
    'entropy' : lambda chunk: Percentage(entropy(chunk)),
    'ic'      : lambda chunk: Percentage(index_of_coincidence(chunk)),
    'crc32'   : lambda chunk: F'{zlib.crc32(chunk)&0xFFFFFFFF:08X}',
    'sha1'    : lambda chunk: hashlib.sha1(chunk).hexdigest(),
    'sha256'  : lambda chunk: hashlib.sha256(chunk).hexdigest(),
    'md5'     : lambda chunk: hashlib.md5(chunk).hexdigest(),
    'index'   : NotImplemented,
}


def LazyMetaOracleFactory(chunk, ghost: bool = False, aliases: Optional[Dict[str, str]] = None):
    """
    Create a dictionary that can be queried lazily for all potential options of the common meta
    variable unit. For example, a SHA-256 hash is computed only as soon as the oracle is accessed
    at the key 'sha256'.
    """
    aliases = aliases or {}

    CUSTOM_TYPE_MAP = {
        'entropy': Percentage,
        'size': SizeInt,
    }

    class LazyMetaOracle(dict):
        def fix(self):
            for key, value in self.items():
                ctype = CUSTOM_TYPE_MAP.get(key)
                if ctype and not isinstance(value, ctype):
                    self[key] = ctype(value)
            return self

        def format(self, spec: str, data: ByteString, codec: str) -> str:
            def identity(x):
                return x
            for key, value in self.items():
                if isbuffer(value):
                    self[key] = ByteStringWrapper(value, codec)
            formatter = string.Formatter()
            data = ByteStringWrapper(data, codec)
            with StringIO() as stream:
                for prefix, field, modifier, conversion in formatter.parse(spec):
                    stream.write(prefix)
                    converter = {
                        'a': ascii,
                        's': str,
                        'r': repr,
                    }.get(conversion, identity)
                    if field is None:
                        continue
                    output = converter(self[field] if field else data)
                    stream.write(output.__format__(modifier))
                return stream.getvalue()

        def __missing__(self, key):
            deduction = COMMON_PROPERTIES.get(key)
            if deduction is NotImplemented:
                raise KeyError(F'cannot deduce the {key} property from just the data, you have to use the cm unit.')
            if deduction:
                return self.setdefault(key, deduction(chunk))
            try:
                return PythonExpression.evaluate(key, **self)
            except ParserError:
                pass
            if key in aliases:
                return self[aliases[key]]
            if ghost:
                return GhostField(key)
            raise KeyError(F'The meta variable {key} is unknown.')

    return LazyMetaOracle


def GetMeta(chunk, *pre_populate, ghost: bool = False, aliases: Optional[Dict[str, str]] = None):
    aliases = aliases or None
    cls = LazyMetaOracleFactory(chunk, ghost, aliases)
    meta = cls(**getattr(chunk, 'meta', {}))
    for key in pre_populate:
        meta[key]
    return meta.fix()
