#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from itertools import cycle
from operator import (
    __add__,
    __sub__,
    __xor__,
)

from ... import arg, Unit
from ....lib.decorators import unicoded


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
        key: arg(type=str, help='The encryption key'),
        alphabet: arg(
            help='The alphabet, by default the Latin one is used: "{default}"'
        ) = 'abcdefghijklmnopqrstuvwxyz',
        operator: arg.choice('-:', choices=['add', 'sub', 'xor'], metavar='OP', help=(
            'Choose the vigenere block operation. The default is {default}, and the available options are: {choices}')) = 'add',
        case_sensitive: arg.switch('-c', help=(
            'Unless this option is set, the key will be case insensitive. Uppercase letters from the input are transformed '
            'using the same shift as would be the lowercase variant, but case is retained.')) = False,
        ignore_unknown: arg.switch('-i', help=(
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
        if not case_sensitive:
            key = key.lower()
            alphabet = alphabet.lower()
            if len(set(alphabet)) != len(alphabet):
                raise ValueError('Duplicate entries detected in alphabet.')
        if not set(key) <= set(alphabet):
            raise ValueError('key contains letters which are not from the given alphabet')
        self.superinit(super(), **vars())

    def _tabula_recta(self, data, reverse=True):
        keystream = cycle(self.args.key)
        alphabet_size = len(self.args.alphabet)
        op = self.args.operator
        if reverse:
            op = _opeator_inverse[op]
        for letter in data:
            uppercase = not self.args.case_sensitive and letter.isupper()
            if uppercase:
                letter = letter.lower()
            try:
                position = self.args.alphabet.index(letter)
            except ValueError:
                yield letter
                if not self.args.ignore_unknown:
                    next(keystream)
                continue
            shift = self.args.alphabet.index(next(keystream))
            result = self.args.alphabet[op(position, shift) % alphabet_size]
            yield result.upper() if uppercase else result

    @unicoded
    def process(self, data):
        return ''.join(self._tabula_recta(data, True))

    @unicoded
    def reverse(self, data):
        return ''.join(self._tabula_recta(data, False))
