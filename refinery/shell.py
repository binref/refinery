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

from functools import WRAPPER_ASSIGNMENTS, cache, wraps

from refinery.__unit__ import UNITS

__all__ = list(UNITS)


__WRAP_UPDATE = ()
__WRAP_ASSIGN = WRAPPER_ASSIGNMENTS + ('__firstlineno__',)


class __pdoc3__:
    def __class_getitem__(cls, *_):
        return ''


def _assembled(cls, *args, **kwargs):
    """
    Creates an instance of the unit that the given class wraps from command line arguments.
    """
    return cls.__wrapped__.assemble(*args, **kwargs)


@cache
def __getattr__(name):
    """
    Loads the unit with the given name, wrapped so that it takes its arguments as they are given on
    the command line. Each unit is wrapped once.
    """
    import refinery
    unit = refinery.load(name)

    if unit is None:
        raise AttributeError(name)

    wrapped_unit = type('_unit', (unit,), {'__new__': _assembled})
    return wraps(unit, updated=__WRAP_UPDATE, assigned=__WRAP_ASSIGN)(wrapped_unit)


def __dir__():
    return __all__
