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
        def __missing__(self, key):
            if key == 'size':
                return self.setdefault(key, len(chunk))
            if key in ('mime', 'ext', 'magic'):
                info = FileMagicInfo(chunk)
                self['mime'] = info.mime
                self['ext'] = info.extension
                self['magic'] = info.description
                return self[key]
            if key == 'entropy':
                return self.setdefault(key, entropy(chunk))
            if key == 'crc32':
                return self.setdefault('crc32', F'{zlib.crc32(chunk)&0xFFFFFFFF:08X}')
            if key == 'sha1':
                return self.setdefault('sha1', hashlib.sha1(chunk).hexdigest())
            if key == 'sha256':
                return self.setdefault('sha256', hashlib.sha256(chunk).hexdigest())
            if key == 'md5':
                return self.setdefault('md5', hashlib.md5(chunk).hexdigest())
            if key in aliases:
                return self[aliases[key]]
            raise KeyError(F'The meta variable {key} is unknown.')

    return LazyMetaOracle
