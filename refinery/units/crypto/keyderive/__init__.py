#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Implements key derivation routines. These are mostly meant to be used as
modifiers for multibin expressions that can be passed as key arguments to
modules in `refinery.units.crypto.cipher`.
"""
from ... import Unit
from ....lib.argformats import multibin, number

try:
    from Crypto.Hash import SHA as SHA1
except ImportError:
    from Crypto.Hash import SHA1

from enum import Enum
from Crypto.Hash import MD2, MD4, MD5, SHA256, SHA512, SHA224, SHA384


__all__ = ['HashAlgorithms', 'KeyDerivation']


class HashAlgorithms(Enum):
    MD2 = MD2
    MD4 = MD4
    MD5 = MD5
    SHA256 = SHA256
    SHA512 = SHA512
    SHA224 = SHA224
    SHA384 = SHA384


class KeyDerivation(Unit, abstract=True):
    _DEFAULT_SALT = NotImplemented
    _DEFAULT_HASH = NotImplemented
    _DEFAULT_ITER = NotImplemented
    _DEFAULT_SIZE = None

    def interface(self, argp):
        kw = dict(
            type=number,
            help='The number of bytes to generate.'
        )
        if self._DEFAULT_SIZE is not None:
            hlp = F'The default is {self._DEFAULT_SIZE}.'
            kw.update(dict(
                default=self._DEFAULT_SIZE,
                nargs='?',
                help=F'{kw["help"]} {hlp}'
            ))
        argp.add_argument('size', **kw)

        if self._DEFAULT_SALT is not NotImplemented:
            kw = dict(
                type=multibin,
                help='Salt for derivation.'
            )
            if self._DEFAULT_SALT is not None:
                hlp = F'Default value is {self._DEFAULT_SALT.hex()} (hex).'
                kw.update(dict(
                    default=self._DEFAULT_SALT,
                    nargs='?',
                    help=F'{kw["help"]} {hlp}'
                ))
            argp.add_argument('salt', **kw)
        if self._DEFAULT_ITER is not NotImplemented:
            hlp = '' if not self._DEFAULT_ITER else F'Default is {self._DEFAULT_ITER}.'
            argp.add_argument(
                '-I', '--iterations',
                metavar='K',
                type=number,
                default=self._DEFAULT_ITER,
                help=F'Optionally specify the number of iterations. {hlp}'
            )
        if self._DEFAULT_HASH is not NotImplemented:
            argp.add_argument(
                '-A', '--algorithm',
                default=self._DEFAULT_HASH,
                metavar='A',
                choices=[h.name for h in HashAlgorithms],
                help=(
                    F'Optionally specify the hash algorithm A to use; A may be '
                    F'one of {", ".join(h.name for h in HashAlgorithms)}.'
                )
            )
        return super().interface(argp)

    @property
    def algorithm(self):
        name = getattr(self.args, 'algorithm', None)
        return name and HashAlgorithms[name].value

    @property
    def iterations(self):
        return getattr(self.args, 'iterations', None)

    @property
    def salt(self):
        return getattr(self.args, 'salt', None)
