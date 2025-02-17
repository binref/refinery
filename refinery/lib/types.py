#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Exports two singletons `refinery.lib.types.INF` and `refinery.lib.types.AST`.
Used by `refinery.units.pattern.PatternExtractorBase` as the default values
for certain command line arguments.
"""
from typing import Union, Tuple, Type, Dict, Any, Optional, List
from collections.abc import MutableMapping


ByteStr = Union[bytes, bytearray, memoryview]
BufferOrStr = Union[bytes, bytearray, memoryview, str]

JSON = Optional[Union[str, int, float, bool, Type[None], Dict[str, 'JSON'], List['JSON']]]
JSONDict = Dict[str, JSON]


class Singleton(type):
    """
    A metaclass that can be used to define singleton classes.
    """

    def __new__(meta, name: str, bases: Tuple[Type, ...], namespace: Dict[str, Any]):
        import sys

        def __repr__(self):
            return self.__class__.__name__

        def __new__(cls):
            import gc
            all = (s for s in gc.get_referrers(cls) if isinstance(s, cls))
            try:
                singleton = next(all)
            except StopIteration:
                return super(type, cls).__new__(cls)
            try:
                next(all)
            except StopIteration:
                return singleton
            else:
                raise RuntimeError(F'More than one object of type {name} exist.')

        def __getstate__(self):
            return None

        def __setstate__(self, _):
            pass

        qualname = F'__singleton_{name}'

        namespace.setdefault('__repr__', __repr__)

        namespace.update(
            __new__=__new__,
            __slots__=(),
            __getstate__=__getstate__,
            __setstate__=__setstate__,
            __qualname__=qualname
        )
        cls = type.__new__(meta, name, bases, namespace)
        setattr(sys.modules[cls.__module__], qualname, cls)
        return cls()


class _INF(metaclass=Singleton):
    def __lt__(self, other): return False
    def __le__(self, other): return False
    def __gt__(self, other): return True
    def __ge__(self, other): return True
    def __eq__(self, other): return other is INF
    def __rmul__(self, other): return self
    def __radd__(self, other): return self
    def __mul__(self, other): return self
    def __add__(self, other): return self
    def __sub__(self, other): return self
    def __div__(self, other): return self
    def __mod__(self, other): return self
    def __pow__(self, other): return self
    def __iadd__(self, other): return self
    def __isub__(self, other): return self
    def __imul__(self, other): return self
    def __imod__(self, other): return self
    def __abs__(self): return None
    def __repr__(self): return '∞'
    def __truediv__(self, other): return self
    def __floordiv__(self, other): return self
    def __rrshift__(self, other): return 0
    def __format__(self, *args): return str(self)


INF = _INF
"""
A crude object representing infinity, which is greater than anything it
is compared to, and only equal to itself.
"""


class _AST(metaclass=Singleton):
    def __eq__(self, other): return True
    def __ne__(self, other): return False
    def __or__(self, other): return other
    def __contains__(self, other): return True
    def __repr__(self): return '*'


AST = _AST
"""
A wildcard object which is equal to everything.
"""


class bounds:
    """
    Can be used to specify certain upper and lower bounds. For example, the following is `True`:

        5 in bounds[3:5]

    This is notably different from how a `range` object functions since the upper bound is included
    in the valid range.
    """

    def __class_getitem__(cls, bounds):
        return cls(bounds)

    def __init__(self, bounds: slice):
        start, stop, step = bounds.start, bounds.stop, bounds.step
        for field in (start, stop, step):
            if field is not None and not isinstance(field, int):
                raise TypeError(field)
        self.min = start or 0
        self.max = stop
        self.inc = step or 1
        if self.max is None:
            self.max = INF
        if self.max < self.min:
            raise ValueError(F'The maximum {self.max} is lesser than the minimum {self.min}.')
        if self.inc < 0:
            raise ValueError('Negative step size not supported for range expressions.')

    def __iter__(self):
        k = self.min
        m = self.max
        i = self.inc
        while k <= m:
            yield k
            k += i

    def __contains__(self, value: int):
        if value < self.min:
            return False
        if value > self.max:
            return False
        return (value - self.min) % self.inc == 0


class _NoMask(metaclass=Singleton):
    def __rand__(self, other):
        return other

    def __and__(self, other):
        return other


NoMask = _NoMask
"""
The value of `NoMask & X` and `X & NoMask` is always equal to `X`. This singleton serves as a
mock bitmask when the value `X` should not be masked at all.
"""


class RepeatedInteger(int):
    """
    This class serves as a dual-purpose result for `refinery.lib.argformats.numseq` types. It
    is an integer, but can be infinitely iterated.
    """
    def __iter__(self): return self
    def __next__(self): return self


class CaseInsensitiveDict(MutableMapping):

    def __init__(self, data=None, **kwargs):
        if isinstance(data, CaseInsensitiveDict):
            self._fold = dict(data._fold)
            self._dict = dict(data._dict)
        else:
            self._fold = dict()
            self._dict = dict()
            self.update(data or {}, **kwargs)

    def __setitem__(self, key: str, value):
        kci = key.casefold()
        self._fold[kci] = key
        self._dict[key] = value

    def __getitem__(self, key: str):
        return self._dict[self._fold[key.casefold()]]

    def __delitem__(self, key: str):
        kci = key.casefold()
        key = self._fold[kci]
        del self._fold[kci]
        del self._dict[key]

    def __iter__(self):
        return iter(self._dict)

    def __len__(self):
        return len(self._dict)

    def casefold(self):
        for kci, key in self._fold.items():
            yield (kci, self._dict[key])

    def __eq__(self, other):
        try:
            other = CaseInsensitiveDict(other)
        except Exception:
            return False
        return dict(self.casefold()) == dict(other.casefold())

    def copy(self):
        return CaseInsensitiveDict(self)

    def __repr__(self):
        return repr(self._dict)
