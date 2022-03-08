#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import abc
import re
import io

from functools import wraps
from typing import ByteString, Callable
from zlib import crc32

from refinery.units import arg, Unit, RefineryPartialResult
from refinery.lib.decorators import unicoded


__all__ = [
    'Deobfuscator',
    'IterativeDeobfuscator',
    'outside',
    'unicoded',
]


class AutoDeobfuscationTimeout(RefineryPartialResult):
    def __init__(self, partial):
        super().__init__('The deobfuscation timeout was reached before the data stabilized.', partial=partial)


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
                    out.write(m[0])
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

    @abc.abstractmethod
    def deobfuscate(self, data: str) -> str:
        return data


class IterativeDeobfuscator(Deobfuscator, abstract=True):

    def __init__(self, timeout: arg('-t', help='Maximum number of iterations; the default is 100.') = 100):
        if timeout < 1:
            raise ValueError('The timeout must be at least 1.')
        super().__init__()
        self.args.timeout = timeout

    def process(self, data: ByteString) -> ByteString:
        previous = crc32(data)
        for _ in range(self.args.timeout):
            try:
                data = super().process(data)
            except KeyboardInterrupt:
                raise RefineryPartialResult('Returning partially deobfuscated data', partial=data)
            checksum = crc32(data)
            if checksum == previous:
                break
            previous = checksum
        else:
            raise AutoDeobfuscationTimeout(data)
        return data


class StringLiterals:

    def __init__(self, pattern: str, data: str):
        self.pattern = str(pattern)
        self.update(data)

    def update(self, data):
        self.data = data
        self.ranges = [
            match.span() for match in re.finditer(self.pattern, data)
        ]

    def shift(self, by, start=0):
        for k in range(start, len(self.ranges)):
            a, b = self.ranges[k]
            self.ranges[k] = a + by, b + by

    def outside(self, function: Callable[[re.Match], str]) -> Callable[[re.Match], str]:
        @wraps(function)
        def wrapper(match: re.Match) -> str:
            if match.string != self.data:
                self.update(match.string)
            a, b = match.span()
            for x, y in self.ranges:
                if x > b: break
                if (a in range(x, y) or x in range(a, b)) and (x < a or y > b):
                    return match[0]
            result = function(match)
            if result is not None:
                return result
            return match[0]
        return wrapper

    def __contains__(self, index):
        return any(index in range(*L) for L in self.ranges)

    def get_container(self, offset):
        for k, L in enumerate(self.ranges):
            if offset in range(*L):
                return k
        return None
