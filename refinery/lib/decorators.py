"""
A selection of refinery-specific decorators.
"""
from __future__ import annotations

import codecs
import itertools
import re

from functools import WRAPPER_ASSIGNMENTS, wraps
from typing import TYPE_CHECKING, Any, Callable, TypeVar, cast, overload

if TYPE_CHECKING:
    from refinery.units import Chunk, Unit


_F = TypeVar('_F', bound=Callable)


def wraps_without_annotations(method: Callable) -> Callable[[_F], _F]:
    """
    This decorator works simila to `wraps` from `functools` but does not update the
    type annotations of the wrapped function. This is used in the other decorators
    in this module because they change the function signature.
    """
    assignments = set(WRAPPER_ASSIGNMENTS)
    assignments.discard('__annotations__')
    wrap = wraps(method, assigned=assignments)
    if TYPE_CHECKING:
        wrap = cast('Callable[[_F], _F]', wrap)
    return wrap


@overload
def unicoded(method: Callable[[Any, str], str]) -> Callable[[Any, Chunk], bytes]:
    ...


@overload
def unicoded(method: Callable[[Any, str], str | None]) -> Callable[[Any, Chunk], bytes | None]:
    ...


def unicoded(method: Callable[[Any, str], str | None]) -> Callable[[Any, Chunk], bytes | None]:
    """
    Can be used to decorate a `refinery.units.Unit.process` routine that takes a
    string argument and also returns one. The resulting routine takes a binary buffer
    as input and attempts to decode it as unicode text. If certain characters cannot
    be decoded, then these ranges are skipped and the decorated routine is called
    once for each string patch that was successfully decoded.
    """
    @wraps_without_annotations(method)
    def method_wrapper(self: Unit, data: Chunk) -> bytes | None:
        input_codec = self.codec if any(data[::2]) else 'UTF-16LE'
        partial = re.split(R'([\uDC80-\uDCFF]+)',  # surrogate escape range
            codecs.decode(data, input_codec, errors='surrogateescape'))
        partial[::2] = (method(self, p) or '' if p else '' for p in itertools.islice(iter(partial), 0, None, 2))
        nones = sum(1 for p in partial if p is None)
        if nones == len(partial):
            return None
        if nones >= 1:
            for k, p in enumerate(partial):
                if p is None:
                    partial[k] = ''
        return codecs.encode(''.join(partial), self.codec, errors='surrogateescape')
    return method_wrapper
