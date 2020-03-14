#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import arg, Unit
from ...lib.argformats import number


class base(Unit):
    """
    Encodes and decodes integers in arbitrary base, using the letters of the
    alphabet as an additional possible 26 digits. The largest base that can
    be represented in this manner is 36.
    """

    _DIGITS = B'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'

    def __init__(
        self,
        base: arg(type=number[2:36], help=(
            'Base to be used for conversion; default value of 0 uses common '
            'python syntax such as the 0x prefix for hexadecimal.')) = 0,
        bigendian: arg('-e', '--lend', help=(
            'Use little endian instead of the default big endian byte order')) = True
    ):
        if base and base not in range(2, 37):
            raise ValueError('base may only be an integer between 2 and 36')
        super().__init__(base=base, bigendian=bigendian)

    @property
    def byteorder(self):
        return 'big' if self.args.bigendian else 'little'

    def reverse(self, data):
        self.log_info('using byte order', self.byteorder)
        number = int.from_bytes(data, byteorder=self.byteorder)

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
        return number.to_bytes(size, byteorder=self.byteorder)
