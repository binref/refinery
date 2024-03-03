#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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
__version__ = '0.6.32'
__distribution__ = 'binary-refinery'

from typing import Dict, List, Optional, Type
from importlib import resources
from datetime import datetime
from threading import RLock

import pickle

from refinery.units import Arg, Unit


def _singleton(cls):
    return cls()


@_singleton
class __unit_loader__:
    """
    Every unit can be imported from the refinery base module. The import is performed on demand to
    reduce import times. The library ships with a pickled dictionary that maps unit names to their
    corresponding module path. This data is expected to be stored as `__init__.pkl` in the package
    directory.
    """
    units: Dict[str, str]
    cache: Dict[str, Type[Unit]]
    _lock: RLock = RLock()

    def __init__(self):
        with resources.path(__name__, '__init__.py') as current_file:
            # This is an annoying hack to allow this to work when __init__.pkl does not
            # yet exist during setup. Starting with Python 3.9, we could use the slightly
            # less awkward: resources.files(__name__).joinpath('__init__.pkl')
            self.path = current_file.parent / '__init__.pkl'
        self.reloading = False
        self.loaded = False
        self.units = {}
        self.cache = {}
        self.last_reload = datetime(1985, 8, 5)
        self.load()

    def __enter__(self):
        return self._lock.__enter__()

    def __exit__(self, et, ev, tb):
        return self._lock.__exit__(et, ev, tb)

    def load(self):
        try:
            self.units = pickle.load(self.path.open('rb'))
        except (FileNotFoundError, EOFError):
            self.reload()
        else:
            self.loaded = True

    def clear(self):
        self.loaded = False
        self.units.clear()
        self.cache.clear()

    def save(self):
        try:
            pickle.dump(self.units, self.path.open('wb'))
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
                name = executable.__qualname__
                self.units[name] = executable.__module__
                self.cache[name] = executable
            self.save()
            self.reloading = False

    def resolve(self, name) -> Optional[Unit]:
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
        def _strip(lines):
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
        with __unit_loader__:
            for name in __unit_loader__.units:
                unit = __unit_loader__.resolve(name)
                for base in unit.mro():
                    try:
                        abstractmethods: List[str] = base.__abstractmethods__
                    except AttributeError:
                        break
                    for method in abstractmethods:
                        if method.startswith('_'):
                            continue
                        at = getattr(unit, method, None)
                        bt = getattr(unit.mro()[1], method, None)
                        if at and at is not bt:
                            self[F'{name}.{method}'] = False
                hlp = get_help_string(unit, width=97)
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


def load(name) -> Optional[Unit]:
    with __unit_loader__:
        return __unit_loader__.resolve(name)


def __getattr__(name):
    with __unit_loader__:
        unit = __unit_loader__.resolve(name)
    if unit is None:
        raise AttributeError(name)
    return unit


def __dir__():
    return __all__
