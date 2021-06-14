#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
File type related functions.
"""
import hashlib
import zlib

from .tools import entropy
from .mime import FileMagicInfo


def LazyMetaOracleFactory(chunk, **aliases):
    """
    Create a dictionary that can be queried lazily for all potential options of the common meta
    variable unit. For example, a SHA-256 hash is computed only as soon as the oracle is accessed
    at the key 'sha256'.
    """
    class LazyMetaOracle(dict):
        def magic_info(self):
            try:
                return self._magic_info
            except AttributeError:
                info = self._magic_info = FileMagicInfo(chunk)
                return info

        def __missing__(self, key):
            if key == 'size':
                return self.setdefault(key, len(chunk))
            if key == 'mime':
                return self.setdefault(key, self.magic_info().mime)
            if key == 'ext':
                return self.setdefault(key, self.magic_info().extension)
            if key == 'magic':
                return self.setdefault(key, self.magic_info().description)
            if key == 'entropy':
                return self.setdefault(key, entropy(chunk))
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
    return meta
