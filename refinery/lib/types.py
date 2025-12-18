"""
This module is used as a unified resource for various types that are primarily used for type hints.
It also exports important singleton types used throughout refinery.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, NamedTuple

if TYPE_CHECKING:
    from typing import (
        Annotated,
        Callable,
        ClassVar,
        Collection,
        Generator,
        Iterable,
        Self,
        Union,
    )

    Param = Annotated
    JSON = Union[
        None,
        str,
        int,
        float,
        bool,
        dict[str, 'JSON'],
        list['JSON'],
        # These are superfluous but help the type checker:
        list[int],
        list[str],
        list[float],
        list[bool],
        dict[str, int],
        dict[str, str],
        dict[str, int | str],
    ]
    JSONDict = dict[str, JSON]

    buf = Union[bytes, bytearray, memoryview]
    isq = Union[int, Iterable[int]]

else:
    class __P:
        def __getitem__(self, annotation):
            return annotation[1]

    Param = __P()
    JSON = Any
    JSONDict = Any
    buf = Any
    isq = Any

    Callable = Any
    ClassVar = Any
    Collection = Any
    Iterable = Any
    Self = Any
    Generator = Any


__all__ = [
    'JSON',
    'JSONDict',
    'buf',
    'isq',
    'Param',
    'NamedTuple',
    'Collection',
    'Iterable',
    'Self',
    'Singleton',
    'Generator',
    'ClassVar',
    'Callable',
    'INF',
    'AST',
    'NoMask',
    'RepeatedInteger',
]


class Singleton(type):
    """
    A metaclass that can be used to define singleton classes.
    """

    def __new__(mcs, name: str, bases: tuple[type, ...], namespace: dict[str, Any]):
        def __new__(cls):
            return cls

        def __getstate__(self):
            return None

        def __setstate__(self, _):
            pass

        def __call__(self, *_):
            return self

        namespace.setdefault('__call__', __call__)
        operator_overloads = {}

        for op, method in namespace.items():
            if op[:2] == op[-2:] == '__' and callable(method):
                operator_overloads[op] = method

        if operator_overloads:
            custom_meta_dict = {}
            for method_name, method in operator_overloads.items():
                def make_method(orig_method):
                    def meta_method(cls, *args, **kwargs):
                        return orig_method(cls, *args, **kwargs)
                    return meta_method
                custom_meta_dict[method_name] = make_method(method)
            mcs = type(f'{name}Meta', (mcs,), custom_meta_dict)

        namespace.update(
            __new__=__new__,
            __slots__=(),
            __getstate__=__getstate__,
            __setstate__=__setstate__,
        )

        return type.__new__(mcs, name, bases, namespace)


class _INF(metaclass=Singleton):
    def __lt__(self, _: Any):
        return False

    def __le__(self, _: Any):
        return False

    def __gt__(self, _: Any):
        return True

    def __ge__(self, _: Any):
        return True

    def __eq__(self, other: Any):
        return other is INF

    def __rmul__(self, _: Any):
        return self

    def __radd__(self, _: Any):
        return self

    def __mul__(self, _: Any):
        return self

    def __add__(self, _: Any):
        return self

    def __sub__(self, _: Any):
        return self

    def __div__(self, _: Any):
        return self

    def __mod__(self, _: Any):
        return self

    def __pow__(self, _: Any):
        return self

    def __iadd__(self, _: Any):
        return self

    def __isub__(self, _: Any):
        return self

    def __imul__(self, _: Any):
        return self

    def __imod__(self, _: Any):
        return self

    def __abs__(self):
        return None

    def __repr__(self):
        return '∞'

    def __truediv__(self, _: Any):
        return self

    def __floordiv__(self, _: Any):
        return self

    def __rrshift__(self, _: Any):
        return 0

    def __format__(self, *_):
        return str(self)


INF = _INF()
"""
A crude object representing infinity, which is greater than anything it
is compared to, and only equal to itself.
"""


class _AST(metaclass=Singleton):
    def __eq__(self, _: Any):
        return True

    def __ne__(self, _: Any):
        return False

    def __or__(self, x: Any):
        return x

    def __contains__(self, _: Any):
        return True

    def __repr__(self):
        return '*'


AST = _AST()
"""
A wildcard object which is equal to everything.
"""


class _NoMask(metaclass=Singleton):
    def __rand__(self, other):
        return other

    def __and__(self, other):
        return other


NoMask = _NoMask()
"""
The value of `NoMask & X` and `X & NoMask` is always equal to `X`. This singleton serves as a
mock bitmask when the value `X` should not be masked at all.
"""


class RepeatedInteger(int):
    """
    This class serves as a dual-purpose result for `refinery.lib.argformats.numseq` types. It
    is an integer, but can be infinitely iterated.
    """
    def __iter__(self):
        return self

    def __next__(self):
        return self


class _NoDefault(metaclass=Singleton):
    pass


NoDefault = _NoDefault()
"""
A sentinel singleton that can be used as a no-default marker when "None" is a valid option.
"""
