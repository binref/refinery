#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import arg, Unit


class base(Unit):
    """
    Encodes and decodes integers in arbitrary base.
    """

    _DEFAULT_APHABET = B'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'

    def __init__(
        self,
        base: arg.number(bound=(2, None), metavar='base', help=(
            'Base to be used for conversion; The value defaults to the length of the alphabet '
            'if given, or 0 otherwise. Base 0 treats the input as a Python integer literal.')) = 0,
        little_endian: arg('-e', help='Use little endian instead byte order.') = False,
        alphabet: arg('-a', metavar='STR', help=(
            'The alphabet of digits. Has to have length at least equal to the chosen base. '
            'The default is: 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ.')) = B'',
    ):
        if alphabet:
            if len(alphabet) < 2:
                raise ValueError('an alphabet with at least two digits is required')
            if not base:
                base = len(alphabet)
        else:
            alphabet = self._DEFAULT_APHABET
        if base and base not in range(2, len(alphabet) + 1):
            raise ValueError(F'base may only be an integer between 2 and {len(alphabet)}')
        super().__init__(base=base, little_endian=little_endian, alphabet=alphabet)

    @property
    def byteorder(self):
        return 'little' if self.args.little_endian else 'big'

    def reverse(self, data):
        self.log_info('using byte order', self.byteorder)
        number = int.from_bytes(data, byteorder=self.byteorder)

        if number == 0:
            return B'0'
        if self.args.base == 0:
            return B'0x%X' % number
        if self.args.base > len(self.args.alphabet):
            raise ValueError(
                F'Only {len(self.args.alphabet)} available; not enough to '
                F'encode base {self.args.base}'
            )

        def reverse_result(number):
            while number:
                yield self.args.alphabet[number % self.args.base]
                number //= self.args.base

        return bytes(reversed(tuple(reverse_result(number))))

    def process(self, data):
        data = data.strip()
        base = self.args.base
        defaults = self._DEFAULT_APHABET[:base]
        alphabet = self.args.alphabet[:base]
        if len(alphabet) == len(defaults):
            if alphabet != defaults:
                self.log_info('translating input data to a default alphabet for faster conversion')
                data = data.translate(bytes.maketrans(alphabet, defaults))
            result = int(data, self.args.base)
        else:
            self.log_warn('very long alphabet, unable to use built-ins; reverting to (slow) fallback.')
            result = 0
            alphabet = {digit: k for k, digit in enumerate(alphabet)}
            for digit in data:
                result *= base
                result += alphabet[digit]
        size, rest = divmod(result.bit_length(), 8)
        size += int(bool(rest))
        return result.to_bytes(size, byteorder=self.byteorder)
