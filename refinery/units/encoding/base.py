#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import Unit
from ...lib.argformats import number


class base(Unit):
    """
    Encodes and decodes integers in arbitrary base, using the letters of the
    alphabet as an additional possible 26 digits. The largest base that can
    be represented in this manner is 36.
    """

    _DIGITS = B'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'

    def interface(self, argp):
        argp.add_argument(
            '-e',
            '--little-endian',
            dest='byteorder',
            action='store_const',
            const='little',
            help='use little endian instead of the default big endian byte order.'
        )
        argp.add_argument(
            'base',
            type=number[2:36],
            default=0,
            nargs='?',
            help='base to be used for conversion; default value of 0 '
                 'uses common python syntax such as the 0x prefix for hexadecimal.'
        )
        argp.set_defaults(byteorder='big')
        return super().interface(argp)

    def reverse(self, data):
        self.log_info('using byte order', self.args.byteorder)
        number = int.from_bytes(data, byteorder=self.args.byteorder)

        if number == 0:
            return B'0'
        if self.args.base == 0:
            return B'0x%X' % number
        if self.args.base > len(self._DIGITS):
            raise ValueError(
                F'Only {len(self._DIGITS)} available; not enough to '
                F'encode base {self.args.base}'
            )

        def reverse_result(number):
            while number:
                yield self._DIGITS[number % self.args.base]
                number //= self.args.base

        return bytes(reversed(tuple(reverse_result(number))))

    def process(self, data):
        data = data.strip()
        number = int(data, self.args.base)
        size, rest = divmod(number.bit_length(), 8)
        if rest: size += 1
        return number.to_bytes(size, byteorder=self.args.byteorder)
