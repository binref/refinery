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

__version__ = '0.9.24'
__distribution__ = 'binary-refinery'

import pickle

from datetime import datetime
from threading import RLock
from typing import TYPE_CHECKING, Iterable, TypeVar, cast

from refinery.lib import resources
from refinery.units import Arg, Unit

if TYPE_CHECKING:
    from pathlib import Path


_T = TypeVar('_T')


def _singleton(cls: type[_T]) -> _T:
    return cls()


@_singleton
class __unit_loader__:
    """
    Every unit can be imported from the refinery base module. The import is performed on demand to
    reduce import times. The library ships with a pickled dictionary that maps unit names to their
    corresponding module path. This data is stored as `units.pkl` in the data directory.
    """
    units: dict[str, str]
    cache: dict[str, type[Unit]]
    _lock: RLock = RLock()

    def __init__(self):
        self.path = resources.datapath('units.pkl')
        self.reloading = False
        self.loaded = False
        self.units = {}
        self.cache = {}
        self.last_reload = datetime(1985, 8, 5)
        self.load()

    def __enter__(self):
        self._lock.__enter__()
        return self

    def __exit__(self, et, ev, tb):
        return self._lock.__exit__(et, ev, tb)

    def load(self):
        try:
            cache = pickle.load(self.path.open('rb'))
        except (FileNotFoundError, EOFError):
            cache = None
        else:
            try:
                version = cache['version']
            except KeyError:
                cache = None
            else:
                if version != __version__:
                    cache = None
        if cache is None:
            self.reload()
        else:
            self.units = cache['units']
            self.loaded = True

    def clear(self):
        self.loaded = False
        self.units.clear()
        self.cache.clear()

    def save(self):
        try:
            with cast('Path', self.path).open('wb') as out:
                pickle.dump({'units': self.units, 'version': __version__}, out)
        except Exception:
            pass
        else:
            self.loaded = True

    def reload(self):
        if not self.reloading:
            from refinery.lib.loader import get_all_entry_points
            self.reloading = True
            self.clear()
            for executable in get_all_entry_points():
                name = executable.__name__
                self.units[name] = executable.__module__
                self.cache[name] = executable
            self.save()
            self.reloading = False

    def resolve(self, name) -> type[Unit] | None:
        if not self.loaded:
            self.load()
        try:
            module_path = self.units[name]
            module = __import__(module_path, None, None, [name])
            entry = getattr(module, name)
            self.cache[name] = entry
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
        with __unit_loader__ as ul:
            for name in ul.units:
                unit = ul.resolve(name)
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


__all__ = sorted(__unit_loader__.units, key=lambda x: x.lower()) + [
    Unit.__name__, Arg.__name__, '__unit_loader__', '__pdoc__']


def load(name) -> type[Unit] | None:
    with __unit_loader__ as ul:
        return ul.resolve(name)


def __getattr__(name):
    with __unit_loader__ as ul:
        unit = ul.resolve(name)
    if unit is None:
        raise AttributeError(name)
    return unit


def __dir__():
    return __all__
