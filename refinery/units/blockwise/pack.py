#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import struct

from typing import Iterable
from enum import IntEnum

from refinery.units.blockwise import Arg, BlockTransformationBase
from refinery.units.encoding.base import base as BaseUnit
from refinery.lib.argformats import number
from refinery.lib.patterns import formats


class FMode(IntEnum):
    TO_INT = 0
    SINGLE = 1
    DOUBLE = 2


class pack(BlockTransformationBase):
    """
    Scans the input data for numeric constants and packs them into a binary format. This is useful to convert the textual representation of
    an array of numbers into its binary form. For example, `123,34,256,12,1,234` would be transformed into the byte sequence `7B22000C01EA`,
    where `256` was wrapped and packed as a null byte because the default block size is one byte. If the above sequence would be packed
    with options -EB2, the result would be equal to `007B00220100000C000100EA` in hexadecimal.
    """

    def __init__(self,
        base: Arg(type=number[2:36], help=(
            'Find only numbers in given base. Default of 0 means that '
            'common expressions for hexadecimal, octal and binary are '
            'accepted.')) = 0,
        prefix : Arg.Switch('-r', group='FLT', help='Add numeric prefixes like 0x, 0b, and 0o in reverse mode.') = False,
        strict : Arg.Switch('-s', help='Only parse integers that fit in one block of the given block size.') = False,
        width  : Arg.Number('-w', help='Pad numbers with the specified amount of leading zeros.') = 0,
        single_floats: Arg.Switch('-f', group='FLT', help='Pack single-precision floating-point numbers. Implies -B4.') = False,
        double_floats: Arg.Switch('-d', group='FLT', help='Pack double-precision floating-point numbers. Implies -B8.') = False,
        bigendian=False, blocksize=1
    ):
        if single_floats and double_floats:
            raise ValueError('The floats and doubles option are mutually exclusive.')
        elif single_floats:
            fmode = FMode.SINGLE
            blocksize = 4
        elif double_floats:
            fmode = FMode.DOUBLE
            blocksize = 8
        else:
            fmode = FMode.TO_INT
        super().__init__(
            base=base,
            prefix=prefix,
            strict=strict,
            width=width,
            bigendian=bigendian,
            blocksize=blocksize,
            fmode=fmode
        )

    @property
    def bytestream(self):
        # never alow bytes to be left unchunked
        return False

    def reverse(self, data):
        base = self.args.base or 10
        width = self.args.width
        mode: FMode = self.args.fmode
        prefix = B''

        self.log_debug(F'using base {base:d}')

        if self.args.prefix:
            prefix = {
                0x02: b'0b',
                0x08: b'0o',
                0x10: b'0x'
            }.get(base, B'')

        if mode is FMode.TO_INT:
            converter = BaseUnit(
                base,
                little_endian=not self.args.bigendian,
                strip_padding=True,
            )
            for n in self.chunk(data, raw=True):
                converted = converter.reverse(n)
                if width:
                    converted = converted.rjust(width, B'0')
                if prefix:
                    converted = prefix + converted
                yield converted
            return

        elif mode is FMode.SINGLE:
            float_format = 'f'
            float_size = 4

        elif mode is FMode.DOUBLE:
            float_format = 'd'
            float_size = 8

        count, rest = divmod(len(data), float_size)
        if rest:
            self.log_warn(F'data contained {rest} trailing bytes that were ignored')
            data = memoryview(data)[:-rest]
        float_format *= count
        if self.args.bigendian:
            float_format = F'>{float_format}'
        else:
            float_format = F'<{float_format}'
        for n in struct.unpack(float_format, data):
            yield str(n).encode(self.codec)

    def process(self, data):
        base: int = self.args.base
        strict: bool = self.args.strict
        mode: FMode = self.args.fmode
        ep = '>' if self.args.bigendian else '<'

        def evaluate_literals(literals: Iterable[bytes]):
            for literal in literals:
                if mode is FMode.TO_INT:
                    if base == 0 and literal[0] == 0x30 and literal[1:].isdigit():
                        literal = B'0o%s' % literal
                    N = int(literal, base)
                elif mode is FMode.SINGLE:
                    N, = struct.unpack(F'{ep}I', struct.pack(F'{ep}f', float(literal)))
                elif mode is FMode.DOUBLE:
                    N, = struct.unpack(F'{ep}Q', struct.pack(F'{ep}d', float(literal)))
                else:
                    raise TypeError('unexpected floating point mode')
                M = N & self.fmask
                if strict and M != N:
                    continue
                yield M

        if base == 0:
            pattern = formats.number
        elif base <= 10:
            pattern = re.compile(B'[-+]?[0-%d]{1,64}' % (base - 1))
        else:
            pattern = re.compile(B'[-+]?[0-9a-%c]{1,20}' % (0x57 + base), re.IGNORECASE)

        return self.unchunk(evaluate_literals(m[0] for m in pattern.finditer(data)))
