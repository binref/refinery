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

from typing import Dict, Optional, ByteString

from .tools import isbuffer, entropy, index_of_coincidence
from .mime import FileMagicInfo
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
        @property
        def magic_info(self):
            try:
                return self._magic_info
            except AttributeError:
                info = self._magic_info = FileMagicInfo(chunk)
                return info

        @magic_info.setter
        def magic_info(self, info):
            self._magic_info = info

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
            if key == 'size':
                return self.setdefault(key, SizeInt(len(chunk)))
            if key == 'mime':
                return self.setdefault(key, self.magic_info.mime)
            if key == 'ext':
                return self.setdefault(key, self.magic_info.extension)
            if key == 'magic':
                return self.setdefault(key, self.magic_info.description)
            if key == 'entropy':
                return self.setdefault(key, Percentage(entropy(chunk)))
            if key == 'ic':
                return self.setdefault(key, Percentage(index_of_coincidence(chunk)))
            if key == 'crc32':
                return self.setdefault(key, F'{zlib.crc32(chunk)&0xFFFFFFFF:08X}')
            if key == 'sha1':
                return self.setdefault(key, hashlib.sha1(chunk).hexdigest())
            if key == 'sha256':
                return self.setdefault(key, hashlib.sha256(chunk).hexdigest())
            if key == 'md5':
                return self.setdefault(key, hashlib.md5(chunk).hexdigest())
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
