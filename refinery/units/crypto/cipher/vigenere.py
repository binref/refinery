#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from itertools import cycle

from ... import arg, Unit
from ....lib.decorators import unicoded


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
        case_sensitive: arg.switch('-c', help=(
            'Unless this option is set, the key will be case insensitive and '
            'the alphabet is assumed to contain only lowercase letters. Any '
            'uppercase letter is transformed using the same shift as would be '
            'the lowercase variant, but case is retained.'
        )) = False,
        ignore_unknown: arg.switch('-i', help=(
            'Unless this option is set, the key stream will be iterated even '
            'for letters that are not contained in the alphabet.'
        )) = False
    ):
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
            if reverse:
                position -= shift
            else:
                position += shift
            result = self.args.alphabet[position % alphabet_size]
            yield result.upper() if uppercase else result

    @unicoded
    def process(self, data):
        return ''.join(self._tabula_recta(data, True))

    @unicoded
    def reverse(self, data):
        return ''.join(self._tabula_recta(data, False))
