#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from itertools import cycle

from ... import Unit
from ....lib.decorators import unicoded


class vigenere(Unit):
    """
    Encryption and decryption using the Vigenère-Bellaso polyalphabetic cipher.
    """

    @classmethod
    def interface(cls, argp):
        argp.add_argument(
            '-c', '--case-sensitive',
            action='store_true',
            help='Unless this option is set, the key will be case insensitive and '
                 'the alphabet is assumed to contain only lowercase letters. Any '
                 'uppercase letter is transformed using the same shift as would be '
                 'the lowercase variant, but case is retained.'
        )
        argp.add_argument(
            '-i', '--ignore-unknown',
            action='store_true',
            help='Unless this option is set, the key stream will be iterated even '
                 'for letters that are not contained in the alphabet.'
        )
        argp.add_argument(
            'key', type=str, help='The encryption key')
        argp.add_argument(
            'alphabet',
            type=str,
            nargs='?',
            default='abcdefghijklmnopqrstuvwxyz',
            help='The alphabet which should be used, default is the Latin one: '
                 '"abcdefghijklmnopqrstuvwxyz"'
        )
        return super().interface(argp)

    def __init__(self, *args, **kw):
        super().__init__(*args, **kw)
        if not self.args.case_sensitive:
            self.args.key = self.args.key.lower()
        alphabet = ''
        for c in self.args.alphabet:
            if not self.args.case_sensitive:
                c = c.lower()
            if c not in alphabet:
                alphabet += c
        if alphabet != self.args.alphabet:
            self.log_warn(F'correcting alphabet to: {alphabet}')
            self.args.alphabet = alphabet
        if not set(self.args.key) <= set(self.args.alphabet):
            raise ValueError('key contains letters which are not from the given alphabet')

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
