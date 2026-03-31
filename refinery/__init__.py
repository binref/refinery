R"""
    ----------------------------------------------------------
            __     __  High Octane Triage Analysis          __
            ||    _||______ __       __________     _____   ||
            ||    \||___   \__| ____/   ______/___ / ____\  ||
    ========||=====||  | __/  |/    \  /==|  / __ \   __\===]|
            '======||  |   \  |   |  \_  _| \  ___/|  |     ||
                   ||____  /__|___|__/  / |  \____]|  |     ||
    ===============''====\/=========/  /==|__|=====|__|======'
                                   \  /
                                    \/

This is the binary refinery package documentation; see
 [GitHub](https://github.com/binref/refinery/) and
 [PyPi](https://pypi.org/project/binary-refinery/)
for more information.

The package `refinery` exports all `refinery.units.Unit`s which are of type `refinery.units.Entry`;
this marker implies that the unit exposes a shell command. The command line interface for each of
these units is given below, this is the same text as would be available by executing the command
with the `-h` or `--help` option. The documentation for this module only lists the classes that
correspond to exported refinery units, but for convenience, the `refinery` module also exports the
classes `refinery.units.Unit` and `refinery.units.Arg`.

To better understand how the command line parameters are parsed, it is also recommended to study
the module documentation of the following library modules, as their content is relevant for how the
various `refinery.units.Unit`s can be combined.

1. `refinery.lib.frame`: framing syntax for working on lists of binary chunks
2. `refinery.lib.argformats`: the multibin syntax for refinery arguments
3. `refinery.lib.meta`: defining and using metadata variables within frames
4. `refinery.units`: writing custom units, add command-line arguments, and how to use refinery
   units within Python code.
"""
from __future__ import annotations

__version__ = '0.10.10'
__distribution__ = 'binary-refinery'

from typing import Iterable, TypeVar

try:
    from refinery.__unit__ import UNITS
except ModuleNotFoundError:
    UNITS: dict[str, str] = {}
finally:
    CACHE: dict[str, type[Unit]] = {}

from refinery.units import Arg, Unit

_T = TypeVar('_T')


def _singleton(cls: type[_T]) -> _T:
    return cls()


def _resolve(name: str) -> type[Unit] | None:
    try:
        return CACHE[name]
    except KeyError:
        pass
    try:
        module_path = UNITS[name]
        module = __import__(module_path, None, None, [name])
        entry = getattr(module, name)
        CACHE[name] = entry
        return entry
    except (KeyError, ModuleNotFoundError):
        return None


@_singleton
class __pdoc__(dict):
    def __init__(self, *a, **kw):
        super().__init__()
        self._loaded = False

    def _strip_globals(self, hlp: str):
        def _strip(lines: Iterable[str]):
            triggered = False
            for line in lines:
                if triggered:
                    if line.lstrip() != line:
                        continue
                    triggered = False
                if line.lower().startswith('global options:'):
                    triggered = True
                    continue
                yield line
        return ''.join(_strip(hlp.splitlines(keepends=True)))

    def _load(self):
        if self._loaded:
            return
        from .explore import get_help_string
        self['Unit'] = False
        self['Arg'] = False
        for name in UNITS:
            unit = _resolve(name)
            if unit is None:
                continue
            for base in unit.mro():
                try:
                    abstractmethods: list[str] = base.__abstractmethods__
                except AttributeError:
                    break
                for method in abstractmethods:
                    if method.startswith('_'):
                        continue
                    at = getattr(unit, method, NotImplemented)
                    bt = getattr(unit.mro()[1], method, None)
                    if at is NotImplemented:
                        continue
                    if at is None:
                        continue
                    if at is not bt:
                        self[F'{name}.{method}'] = False
            if hlp := get_help_string(unit, width=97):
                hlp = hlp.replace('\x60', '')
                hlp = self._strip_globals(hlp).strip()
                hlp = (
                    F'This unit is implemented in `{unit.__module__}` and has the following '
                    F'commandline Interface:\n```text\n{hlp}\n```'
                )
                self[name] = hlp
        self._loaded = True

    def items(self):
        self._load()
        return super().items()


__all__ = list(UNITS) + [Unit.__name__, Arg.__name__, '__pdoc__']


def load(name) -> type[Unit] | None:
    return _resolve(name)


def __getattr__(name):
    unit = _resolve(name)
    if unit is None:
        raise AttributeError(name)
    return unit


def __dir__():
    return __all__
