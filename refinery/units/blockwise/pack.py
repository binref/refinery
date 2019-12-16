#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from . import BlockTransformation
from ...lib.argformats import number
from ...lib.patterns import formats
from ..encoding.base import base as base_unit


class pack(BlockTransformation):
    """
    Scans the input data for numeric constants and packs them into a binary
    format. This is useful to convert the textual representation of an array of
    numbers into its binary form. For example, `123,34,256,12,1,234` would be
    transformed into the byte sequence `7B22000C01EA`, where `256` was wrapped
    and packed as a null byte because the default block size is one byte. If
    the above sequence would be packed with options -EB2, the result would be
    equal to `007B00220100000C000100EA` in hexadecimal.
    """

    def interface(self, argp):
        base = argp.add_argument_group(
            'Number Base Options',
            'Up to base 36 is supported by extending the decimal digits with '
            'case-insensitive alphabetic characters A through Z.'
        ).add_mutually_exclusive_group()
        base.add_argument(
            'base',
            type=number[2:36],
            default=0,
            nargs='?',
            help='Find only numbers in given base. Default of 0 means that '
                 'common expressions for hexadecimal, octal and binary are '
                 'accepted.')
        base.add_argument(
            '-x', '--hexdump',
            action='store_true',
            help='Only look for exactly two digit hexadecimal numbers surrounded by whitespace.'
        )
        rev = argp.add_argument_group(
            'Reverse Options',
            'The following options only apply to reverse mode.'
        )
        rev.add_argument('-P', '--no-prefix', action='store_true',
            help='Does not automatically add numeric prefixes in reverse mode')
        return super().interface(argp)

    @property
    def bytestream(self):
        # never alow bytes to be left unchunked
        return False

    def reverse(self, data):
        base = self.args.base or 10
        prefix = B''

        self.log_debug(F'using base {base:d}')

        if not self.args.no_prefix:
            prefix = {
                0x02: b'0b',
                0x08: b'0o',
                0x10: b'0x'
            }.get(base, B'')

        converter = base_unit(
            base=base,
            byteorder=('big', 'little')[self.args.little_endian]
        )

        for n in self.chunk(data, raw=True):
            yield prefix + converter.reverse(n)

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        if self.args.hexdump:
            self.log_debug('enabling hexdump parser')
            self.args.base = 0x10

    def process(self, data):
        if self.args.hexdump:
            pattern = re.compile(BR'(?:\s|^)(?:0x)?([0-9a-f]{%i})h?(?=\s|$)' % (self.args.blocksize * 2), re.IGNORECASE)
        elif self.args.base == 0:
            pattern = formats.integer
        elif self.args.base <= 10:
            pattern = re.compile(B'[-+]?[0-%d]{1,64}' % (self.args.base - 1))
        else:
            pattern = re.compile(B'[-+]?[0-9a-%c]{1,20}' % (0x57 + self.args.base), re.IGNORECASE)

        items = pattern.findall(data)
        items = [int(n, self.args.base) & self.fmask for n in items]
        return self.unchunk(items)
