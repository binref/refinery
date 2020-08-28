#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A selection of refinery-specific decorators.
"""
import codecs
import re

from functools import wraps, WRAPPER_ASSIGNMENTS
from typing import Callable, Iterable
from ..units import Unit


def wraps_without_annotations(method: Callable) -> Callable:
    """
    This decorator works simila to `wraps` from `functools` but does not update the
    type annotations of the wrapped function. This is used in the other decorators
    in this module because they change the function signature.
    """
    assignments = set(WRAPPER_ASSIGNMENTS)
    assignments.discard('__annotations__')
    return wraps(method, assigned=assignments)


def unicoded(method: Callable[[Unit, str], str]) -> Callable[[Unit, bytes], bytes]:
    """
    Can be used to decorate a `refinery.units.Unit.process` routine that takes a
    string argument and also returns one. The resulting routine takes a binary buffer
    as input and attempts to decode it as unicode text. If certain characters cannot
    be decoded, then these ranges are skipped and the decorated routine is called
    once for each string patch that was successfully decoded.
    """
    @wraps_without_annotations(method)
    def method_wrapper(self, data: bytes) -> bytes:
        input_codec = self.codec if any(data[::2]) else 'UTF-16LE'
        partial = re.split(R'([\uDC80-\uDCFF]+)',  # surrogate escape range
            codecs.decode(data, input_codec, errors='surrogateescape'))
        partial[::2] = [method(self, p) if p else '' for p in partial[::2]]
        return codecs.encode(''.join(partial),
            self.codec, errors='surrogateescape')
    return method_wrapper


def linewise(method: Callable[[Unit, str], str]) -> Callable[[Unit, bytes], Iterable[bytes]]:
    """
    Can be used to decorate a `refinery.units.Unit.process` routine that takes a
    string argument and also returns one. The resulting routine expects a default
    encoded string input buffer and calls the decorated routine once for each
    line in the corresponding decoded string.
    """
    @wraps_without_annotations(method)
    def method_wrapper(self, data: bytes) -> Iterable[bytes]:
        lines = data.decode(self.codec).splitlines()
        width = len(str(len(lines)))
        for k, line in enumerate(lines):
            try:
                yield method(self, line).encode(self.codec)
            except Exception as E:
                self.log_info(F'error in line {k:0{width}d}: {E}')
    return method_wrapper
