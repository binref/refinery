#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from itertools import cycle
from operator import (
    __add__,
    __sub__,
    __xor__,
)

from refinery.units import Arg, Unit
from refinery.lib.decorators import unicoded


_opeator_inverse = {
    __add__: __sub__,
    __sub__: __add__,
    __xor__: __xor__
}


class vigenere(Unit):
    """
    Encryption and decryption using the Vigenère-Bellaso polyalphabetic cipher.
    """

    def __init__(
        self,
        key: Arg(help='The encryption key'),
        alphabet: Arg(
            help='The alphabet, by default the Latin one is used: "{default}"'
        ) = b'abcdefghijklmnopqrstuvwxyz',
        operator: Arg.Choice('-:', choices=['add', 'sub', 'xor'], metavar='OP', help=(
            'Choose the vigenere block operation. The default is {default}, and the available options are: {choices}')) = 'add',
        case_sensitive: Arg.Switch('-c', help=(
            'Unless this option is set, the key will be case insensitive. Uppercase letters from the input are transformed '
            'using the same shift as would be the lowercase variant, but case is retained.')) = False,
        ignore_unknown: Arg.Switch('-i', help=(
            'Unless this option is set, the key stream will be iterated even '
            'for letters that are not contained in the alphabet.'
        )) = False
    ):
        if not callable(operator):
            operator = {
                'add': __add__,
                'sub': __sub__,
                'xor': __xor__,
            }.get(operator.lower(), None)
            if operator is None:
                raise ValueError(F'The value {operator!r} is not valid as an operator.')
        self.superinit(super(), **vars())

    def _tabula_recta(self, data, reverse=True):
        key: str = self.args.key.decode(self.codec)
        alphabet: str = self.args.alphabet.decode(self.codec)
        operator = self.args.operator
        case_sensitive: bool = self.args.case_sensitive
        ignore_unknown: bool = self.args.ignore_unknown
        if not case_sensitive:
            key = key.lower()
            alphabet = alphabet.lower()
            if len(set(alphabet)) != len(alphabet):
                raise ValueError('Duplicate entries detected in alphabet.')
        if not set(key) <= set(alphabet):
            diff = set(key) - set(alphabet)
            diff = ', '.join(diff)
            raise ValueError(F'key contains letters which are not from the given alphabet: {diff}')
        self.log_info(F'using key {key} and alphabet {alphabet}')
        keystream = cycle(key)
        alph_size = len(alphabet)
        if reverse:
            operator = _opeator_inverse[operator]
        for letter in data:
            uppercase = not case_sensitive and letter.isupper()
            if uppercase:
                letter = letter.lower()
            try:
                position = alphabet.index(letter)
            except ValueError:
                yield letter
                if not ignore_unknown:
                    next(keystream)
                continue
            shift = alphabet.index(next(keystream))
            result = alphabet[operator(position, shift) % alph_size]
            yield result.upper() if uppercase else result

    @unicoded
    def process(self, data):
        return ''.join(self._tabula_recta(data, True))

    @unicoded
    def reverse(self, data):
        return ''.join(self._tabula_recta(data, False))
