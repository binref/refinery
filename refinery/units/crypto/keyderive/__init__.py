#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Implements key derivation routines. These are mostly meant to be used as
modifiers for multibin expressions that can be passed as key arguments to
modules in `refinery.units.crypto.cipher`.
"""
from ... import arg, Unit
from ....lib.argformats import number

try:
    from Crypto.Hash import SHA as SHA1
except ImportError:
    from Crypto.Hash import SHA1

from enum import Enum
from Crypto.Hash import MD2, MD4, MD5, SHA256, SHA512, SHA224, SHA384


__all__ = ['arg', 'HASH', 'KeyDerivation']


class HASH(Enum):
    MD2 = MD2
    MD4 = MD4
    MD5 = MD5
    SHA1 = SHA1
    SHA256 = SHA256
    SHA512 = SHA512
    SHA224 = SHA224
    SHA384 = SHA384


class KeyDerivation(Unit, abstract=True):

    def __init__(
        self,
        size: arg(help='The number of bytes to generate.', type=number),
        salt: arg(help='Salt for the derivation.'),
        hash: arg.option(choices=HASH, metavar='hash',
            help='Specify one of these algorithms (default is {default}): {choices}') = None,
        iter: arg.number(metavar='iter', help='Number of iterations; default is {default}.') = None,
        **kw
    ):
        return super().__init__(salt=salt, size=size, iter=iter, hash=arg.as_option(hash, HASH), **kw)

    @property
    def hash(self): return self.args.hash.value
