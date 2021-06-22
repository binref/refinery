#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
File type related functions.
"""
import abc
import hashlib
import zlib

from .tools import entropy
from .mime import FileMagicInfo


class CustomStringRepresentation(abc.ABC):
    @abc.abstractmethod
    def __str__(self): ...


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


def LazyMetaOracleFactory(chunk, **aliases):
    """
    Create a dictionary that can be queried lazily for all potential options of the common meta
    variable unit. For example, a SHA-256 hash is computed only as soon as the oracle is accessed
    at the key 'sha256'.
    """

    CUSTOM_TYPE_MAP = {
        'entropy': Percentage,
        'size': SizeInt,
    }

    class LazyMetaOracle(dict):
        def magic_info(self):
            try:
                return self._magic_info
            except AttributeError:
                info = self._magic_info = FileMagicInfo(chunk)
                return info

        def fix(self):
            for key, value in self.items():
                ctype = CUSTOM_TYPE_MAP.get(key)
                if ctype and not isinstance(value, ctype):
                    self[key] = ctype(value)
            return self

        def __missing__(self, key):
            if key == 'size':
                return self.setdefault(key, SizeInt(len(chunk)))
            if key == 'mime':
                return self.setdefault(key, self.magic_info().mime)
            if key == 'ext':
                return self.setdefault(key, self.magic_info().extension)
            if key == 'magic':
                return self.setdefault(key, self.magic_info().description)
            if key == 'entropy':
                return self.setdefault(key, Percentage(entropy(chunk)))
            if key == 'crc32':
                return self.setdefault(key, F'{zlib.crc32(chunk)&0xFFFFFFFF:08X}')
            if key == 'sha1':
                return self.setdefault(key, hashlib.sha1(chunk).hexdigest())
            if key == 'sha256':
                return self.setdefault(key, hashlib.sha256(chunk).hexdigest())
            if key == 'md5':
                return self.setdefault(key, hashlib.md5(chunk).hexdigest())
            if key in aliases:
                return self[aliases[key]]
            raise KeyError(F'The meta variable {key} is unknown.')

    return LazyMetaOracle


def GetMeta(chunk, *pre_populate, **aliases):
    cls = LazyMetaOracleFactory(chunk, **aliases)
    meta = cls(**getattr(chunk, 'meta', {}))
    for key in pre_populate:
        meta[key]
    return meta.fix()
