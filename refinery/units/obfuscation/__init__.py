#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import io

from zlib import crc32

from .. import arg, Unit
from ...lib.decorators import unicoded


__all__ = [
    'Deobfuscator',
    'IterativeDeobfuscator'
]


class AutoDeobfuscationTimeout(RuntimeError):
    pass


def outside(*exceptions):
    """
    A decorator which allows to apply the transformation only to areas where
    a set of given regular expressions does not match. Here, this is mostly
    used to apply deobfuscations only to code outside of strings.
    """

    exclusion = '|'.join(F'(?:{e})' for e in exceptions)

    def excluded(method):
        def wrapper(self, data):
            with io.StringIO() as out:
                cursor = 0
                for m in re.finditer(exclusion, data, re.DOTALL):
                    out.write(method(self, data[cursor:m.start()]))
                    out.write(m.group(0))
                    cursor = m.end()
                out.write(method(self, data[cursor:]))
                return out.getvalue()
        return wrapper

    return excluded


class Deobfuscator(Unit, abstract=True):

    def __init__(self): super().__init__()

    @unicoded
    def process(self, data: str) -> str:
        return self.deobfuscate(data)

    def deobfuscate(self, data: str) -> str:
        return data


class IterativeDeobfuscator(Deobfuscator, abstract=True):

    def __init__(self, timeout: arg('-t', help='Maximum number of iterations; the default is 100.') = 100):
        if timeout < 2:
            raise ValueError('The timeout must be at least 2.')
        super().__init__()
        self.args.timeout = timeout

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
