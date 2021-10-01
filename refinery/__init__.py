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

The main package `refinery` exports all `refinery.units.Unit`s which are also
of type `refinery.units.Entry`, i.e. they expose a shell command. The command
line interface for each of these units is given below, this is the same text
as would be available by executing the command with the `-h` or `--help`
option. To better understand how the command line parameters are parsed, it is
recommended to study the module documentation of the following library modules,
as their content is relevant for command line use of the `refinery`.

1. `refinery.lib.frame`
2. `refinery.lib.argformats`
3. `refinery.lib.meta`

Furthermore, the module documentation of `refinery.units` contains a brief
example of how to write simple units.
"""
__version__ = '0.4.5'
__pip_pkg__ = 'binary-refinery'

import pickle
import pkg_resources

from .units import arg, Unit


def _singleton(cls):
    return cls()


UNIT_CACHE_PATH = pkg_resources.resource_filename(__name__, '__init__.pkl')


@_singleton
class _cache:
    """
    Every unit can be imported from the refinery base module. The actual import
    is performed on demand to reduce import times. On first import of the refinery
    package, it creates a map of units and their corresponding module and stores
    this map as `__init__.pkl` in the package directory; this process can take
    several seconds. Subsequent imports of refinery should be faster, and the
    loading of units from the module is nearly as fast as specifying the full path.
    """
    def __init__(self):
        self.reloading = False
        self.loaded = False
        self.units = {}
        self.cache = {}
        self.load()

    def load(self):
        try:
            with open(UNIT_CACHE_PATH, 'rb') as stream:
                self.units = pickle.load(stream)
        except (FileNotFoundError, EOFError):
            self.reload()
        else:
            self.loaded = True

    def save(self):
        try:
            with open(UNIT_CACHE_PATH, 'wb') as stream:
                pickle.dump(self.units, stream)
        except Exception:
            pass
        else:
            self.loaded = True

    def reload(self):
        if not self.reloading:
            from .lib.loader import get_all_entry_points
            self.reloading = True
            self.units = {e.__qualname__: e.__module__ for e in get_all_entry_points()}
            self.reloading = False
            self.save()

    def _resolve(self, name, retry=False):
        if retry:
            self.reload()
        try:
            module_path = self.units[name]
            module = __import__(module_path, None, None, [name])
            entry = getattr(module, name)
            self.cache[name] = entry
            return entry
        except (KeyError, ModuleNotFoundError):
            if not retry:
                return self._resolve(name, retry=True)
            raise AttributeError

    def __getitem__(self, name):
        return self._resolve(name)


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
        for name in _cache.units:
            unit = _cache[name]
            for base in unit.mro():
                try:
                    abstractmethods = base.__abstractmethods__
                except AttributeError:
                    break
                for method in abstractmethods:
                    at = getattr(unit, method, None)
                    bt = getattr(unit.mro()[1], method, None)
                    if at and at is not bt:
                        self[F'{name}.{method}'] = False
            hlp = get_help_string(unit, width=74)
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


def drain(stream):
    """
    A function wrapper around the `bytearray` data type. Can be used as the final sink in
    a refinery pipeline in Python code, i.e.:

        from refinery import *
        # ...
        output = data | carve('b64', single=True) | b64 | zl | drain
        assert isinstance(output, bytearray)
    """
    return bytearray(stream)


__all__ = [x for x, _ in sorted(_cache.units.items(), key=lambda x: x[1])] + [
    Unit.__name__, arg.__name__, '__pdoc__', 'drain', 'UNIT_CACHE_PATH']


def __getattr__(name):
    return _cache[name]


def __dir__():
    return __all__


def load(name):
    if _cache.loaded:
        return _cache.cache.get(name)
    return _cache[name]
