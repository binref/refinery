"""
# Shell-Like Unit Interface

Any unit from the `refinery` module can also be imported from this module. When imported from here,
the units are initialized differently: They can be given string arguments as they would receive on
the command line. For example:

    >>> from refinery.shell import *
    >>> emit('ABC', 'DEF') [ pop('t') | xor('var:t') | pack('-R') ] | str
    '575'

This especially gives easier access to the powerful `refinery.lib.meta` variables and the entire
multibin format expressions, see `refinery.lib.argformats`.
"""
from __future__ import annotations

from functools import WRAPPER_ASSIGNMENTS, wraps

from refinery import __unit_loader__

with __unit_loader__:
    __all__ = sorted(__unit_loader__.units, key=lambda x: x.lower())


__WRAP_UPDATE = ()
__WRAP_ASSIGN = WRAPPER_ASSIGNMENTS + ('__firstlineno__',)


class __pdoc3__:
    def __class_getitem__(cls, *_):
        return ''


def __getattr__(name):
    with __unit_loader__:
        unit = __unit_loader__.resolve(name)

    if unit is None:
        raise AttributeError(name)

    class _unit(unit):
        def __new__(cls, *args, **kwargs):
            return unit.assemble(*args, **kwargs)

    wrapped_unit = wraps(unit, updated=__WRAP_UPDATE, assigned=__WRAP_ASSIGN)(_unit)
    return wrapped_unit


def __dir__():
    return __all__
