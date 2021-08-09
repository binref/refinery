#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Functions to help dynamically load refinery units.
"""
import functools
import importlib
import os
import pkg_resources
import pkgutil
import shlex
import sys
import logging

import refinery

from typing import Iterable, Any


class EntryNotFound(NameError):
    pass


def get_all_entry_points() -> Iterable[type]:
    """
    The function returns an iterator over all entry points, i.e.
    all subclasses of the `refinery.units.Entry` class.
    """
    path = ['refinery', 'units']
    root = __import__('.'.join(path))

    for name in path[1:]:
        root = getattr(root, name)

    def iterate(parent, *path):
        for _, name, ispkg in pkgutil.iter_modules(parent.__path__):
            module_name = '.'.join([*path, name])
            try:
                importlib.import_module(module_name)
                module = getattr(parent, name)
            except ModuleNotFoundError as error:
                logging.error(F'could not load {module_name} because {error.name} is missing.')
                continue
            except Exception as error:
                logging.error(F'could not load {module_name} due to unknown error: {error!s}')
                continue
            if ispkg:
                yield from iterate(module, *path, name)
            for attr in dir(module):
                item = getattr(module, attr)
                if getattr(item, '__module__', None) != module_name:
                    continue
                if isinstance(item, type) and issubclass(item, root.Entry) and item is not root.Entry:
                    yield item

    yield from iterate(root, *path)


def get_entry_point(name: str) -> type:
    """
    Retrieve a refinery entry point by name.
    """
    for package in [refinery.__pip_pkg__, 'refinery']:
        try:
            return pkg_resources.load_entry_point(package, 'console_scripts', name).__self__
        except pkg_resources.DistributionNotFound:
            continue
        except ImportError:
            raise EntryNotFound(F'not a unit: {name}')
        except Exception as error:
            logging.error(F'could not load {package} entry point {name}: {type(error).__name__}: {error!s}')
    if os.environ.get('REFINERY_LOAD_LOCAL', False):
        try:
            from ..units import Entry
            sys.path.append('.')
            module = importlib.import_module(name)
            for attr in dir(module):
                item = getattr(module, attr)
                if getattr(item, '__module__', None) != name:
                    continue
                if isinstance(item, type) and issubclass(item, Entry):
                    return item
        except Exception:
            pass
    for entry in get_all_entry_points():
        if getattr(entry, 'name', None) == name:
            return entry
    raise EntryNotFound('no entry point with name "%s" was found.' % name)


def resolve(name: str) -> type:
    """
    Attempts to import the unit with the given name from the refinery package
    and falls back to using `refinery.lib.loader.get_entry_point` if this fails.
    Raises `refinery.lib.loader.EntryNotFound` if the entry is not found.
    """
    try:
        unit = refinery.load(name)
    except ImportError:
        unit = None
    return unit or get_entry_point(name)


def load(name: str, *args, **kwargs) -> Any:
    """
    Loads the unit specified by `name`, initialized with the given arguments
    and keyword arguments.
    """
    entry = get_entry_point(name)
    return entry.assemble(*args, **kwargs)


def load_commandline(command: str) -> Any:
    """
    Returns a unit as it would be loaded from a given command line string.
    """
    module, *arguments = shlex.split(command)
    return load(module, *arguments)


def load_detached(command: str) -> Any:
    """
    Returns a unit as it would be loaded from a given command line string,
    except that the unit has been detached from the default log level.
    """
    return load_commandline(command).log_detach()


@functools.lru_cache(maxsize=None)
def load_pipeline(commandline: str, pipe='|'):
    """
    Parses a complete pipeline as given on the command line.
    """
    pipeline = None
    command = []
    for parsed, token in zip(
        shlex.split(commandline, posix=True),
        shlex.split(commandline, posix=False)
    ):
        if token == parsed and pipe in token:
            tail, *rest = token.split(pipe)
            *rest, parsed = rest
            if tail:
                command.append(tail)
            pipeline |= load(*command)
            command.clear()
            for name in rest:
                pipeline |= load(name)
            if not parsed:
                continue
        command.append(parsed)
    if command:
        pipeline |= load(*command)
    elif not pipeline:
        return load('nop')
    return pipeline
