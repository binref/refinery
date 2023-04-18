#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Implements various cryptographic hashing algorithms.
"""
import hashlib

from refinery.units.crypto.hash import HashUnit


class md4(HashUnit):
    """
    Returns the MD4 hash of the input data.
    """
    def _algorithm(self, data):
        from Cryptodome.Hash import MD4
        return MD4.new(data)


class md2(HashUnit):
    """
    Returns the MD2 hash of the input data.
    """
    def _algorithm(self, data):
        from Cryptodome.Hash import MD2
        return MD2.new(data)


class md5(HashUnit):
    """
    Returns the MD5 hash of the input data.
    """
    def _algorithm(self, data):
        return hashlib.md5(data)


class sha1(HashUnit):
    """
    Returns the SHA1 hash of the input data.
    """
    def _algorithm(self, data):
        return hashlib.sha1(data)


class sha224(HashUnit):
    """
    Returns the SHA224 hash of the input data.
    """
    def _algorithm(self, data):
        return hashlib.sha224(data)


class sha256(HashUnit):
    """
    Returns the SHA256 hash of the input data.
    """
    def _algorithm(self, data):
        return hashlib.sha256(data)


class sha384(HashUnit):
    """
    Returns the SHA384 hash of the input data.
    """
    def _algorithm(self, data):
        return hashlib.sha384(data)


class sha512(HashUnit):
    """
    Returns the SHA512 hash of the input data.
    """
    def _algorithm(self, data):
        return hashlib.sha512(data)


class blk224(HashUnit):
    """
    Returns the BLK224 hash of the input data.
    """
    def _algorithm(self, data):
        return hashlib.blake2b(data, digest_size=28)


class blk256(HashUnit):
    """
    Returns the BLK256 hash of the input data.
    """
    def _algorithm(self, data):
        return hashlib.blake2b(data, digest_size=32)


class blk384(HashUnit):
    """
    Returns the BLK384 hash of the input data.
    """
    def _algorithm(self, data):
        return hashlib.blake2b(data, digest_size=48)


class blk512(HashUnit):
    """
    Returns the BLK512 hash of the input data.
    """
    def _algorithm(self, data):
        return hashlib.blake2b(data, digest_size=64)


class ripemd160(HashUnit):
    """
    Returns the RIPEMD-160 hash of the input data.
    """
    def _algorithm(self, data):
        from Cryptodome.Hash import RIPEMD160
        return RIPEMD160.new(data)


class ripemd128(HashUnit):
    """
    Returns the RIPEMD-128 hash of the input data.
    """
    def _algorithm(self, data):
        from refinery.lib.ripemd128 import ripemd128
        return ripemd128(data)
