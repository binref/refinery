#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Exports two singletons `refinery.lib.types.INF` and `refinery.lib.types.AST`.
Used by `refinery.units.pattern.PatternExtractorBase` as the default values
for certain command line arguments.
"""
from typing import Union, Tuple, Type, Dict, Any, Optional, List

__all__ = ['INF', 'AST', 'Singleton', 'ByteStr']


ByteStr = Union[bytes, bytearray, memoryview]

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

        qualname = F'_singleton_{name}'

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


class INF(metaclass=Singleton):
    """
    A crude object representing infinity, which is greater than anything it
    is compared to, and only equal to itself.
    """
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
    def __abs__(self): return None
    def __repr__(self): return '∞'
    def __truediv__(self, other): return self
    def __floordiv__(self, other): return self


class AST(metaclass=Singleton):
    """
    A wildcard object which is equal to everything.
    """
    def __eq__(self, other): return True
    def __ne__(self, other): return False
    def __or__(self, other): return other
    def __repr__(self): return '*'
