#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
from zlib import crc32

from .. import Unit
from ...lib.argformats import number
from ...lib.decorators import unicoded


__all__ = [
    'Deobfuscator',
    'IterativeDeobfuscator'
]


class AutoDeobfuscationTimeout(RuntimeError):
    pass


def outside(*args):
    """
    A decorator which allows to apply the transformation only to areas where
    a set of given regular expressions does not match. Here, this is mostly
    used to apply deobfuscations only to code outside of strings.
    """

    exclusion = B'(' + B'|'.join(B'(?:%s)' % a for a in args) + B')'

    def excluded(method):
        def wrapper(self, data):
            split = re.split(exclusion, data, re.DOTALL)
            split[::2] = [method(self, chunk) for chunk in split[::2]]
            return B''.join(split)
        return wrapper

    return excluded


class Deobfuscator(Unit, abstract=True):
    @unicoded
    def process(self, data: str) -> str:
        return self.deobfuscate(data)

    def deobfuscate(self, data: str) -> str:
        return data


class IterativeDeobfuscator(Deobfuscator, abstract=True):

    def interface(self, argp):
        argp.add_argument(
            '-t', '--timeout',
            type=number[2:],
            default=100,
            help='Specify the maximum number of iterations that may be '
                 'performed. The default is 100.'
        )
        return super().interface(argp)

    def process(self, data: bytes) -> bytes:
        previous = crc32(data)
        for _ in range(self.args.timeout):
            data = super().process(data)
            checksum = crc32(data)
            if checksum == previous:
                break
            previous = checksum
        else:
            raise AutoDeobfuscationTimeout()
        return data
