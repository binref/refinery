#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Functions to help dynamically load refinery units.
"""
from __future__ import annotations

import functools
import importlib
import pkgutil
import shlex
import logging

import refinery

from typing import Dict, Iterable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from refinery.units import Executable, Unit


class EntryNotFound(NameError):
    pass


def get_all_entry_points() -> Iterable[Executable]:
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


@functools.lru_cache(maxsize=1, typed=True)
def get_entry_point_map() -> Dict[str, Executable]:
    """
    Returns a dictionary of all available unit names, mapping to the class that implements it.
    The dictionary is cached.
    """
    return {exe.name: exe for exe in get_all_entry_points()}


def get_entry_point(name: str) -> Executable:
    """
    Retrieve a refinery entry point by name.
    """
    unit = getattr(refinery, name, None) or get_entry_point_map().get(name)
    if unit is None:
        raise EntryNotFound(F'no entry point named "{name}" was found.')
    return unit


def resolve(name: str) -> Executable:
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


def load(name: str, *args, **kwargs) -> Unit:
    """
    Loads the unit specified by `name`, initialized with the given arguments
    and keyword arguments.
    """
    entry = get_entry_point(name)
    return entry.assemble(*args, **kwargs)


def load_commandline(command: str) -> Unit:
    """
    Returns a unit as it would be loaded from a given command line string.
    """
    module, *arguments = shlex.split(command)
    return load(module, *arguments)


def load_detached(command: str) -> Unit:
    """
    Returns a unit as it would be loaded from a given command line string,
    except that the unit has been detached from the default log level.
    """
    return load_commandline(command).log_detach()


@functools.lru_cache(maxsize=None)
def load_pipeline(commandline: str, pipe='|') -> Unit:
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
