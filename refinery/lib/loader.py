#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Functions to help dynamically load refinery units.
"""
import pkgutil
import pkg_resources

from typing import Iterable, Any


class EntryNotFound(NameError):
    pass


def get_package_name() -> str:
    """
    Retrieves the toplevel package name.
    """
    root = __name__
    first_dot = root.find('.')
    if first_dot > 0:
        root = root[:first_dot]
    return root


def get_all_entry_points() -> Iterable[type]:
    """
    The function returns an iterator over all entry points, i.e.
    all subclasses of the `refinery.units.Entry` class.
    """
    path = [get_package_name(), 'units']
    root = __import__('.'.join(path))

    for name in path[1:]:
        root = getattr(root, name)

    def iterate(parent, *path):
        for _, name, ispkg in pkgutil.iter_modules(parent.__path__):
            try:
                module_name = '.'.join([*path, name])
                __import__(module_name)
                module = getattr(parent, name)
            except Exception:
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
    try:
        entry = pkg_resources.load_entry_point(
            get_package_name(), 'console_scripts', name).__self__
    except Exception:
        # refinery unit entry points with underscored names will be exposed with
        # these underscores replaced by dashes. If such a name is passed to the
        # loader, the following substitution ensures that it still works.
        name = name.replace('-', '_')
        for entry in get_all_entry_points():
            if getattr(entry, '__name__', None) == name:
                break
        else:
            raise EntryNotFound('no entry point with name "%s" was found.' % name)
    return entry


def resolve(name: str) -> type:
    """
    Attempts to import the unit with the given name from the refinery package
    and falls back to using `refinery.lib.loader.get_entry_point` if this fails.
    Raises `refinery.lib.loader.EntryNotFound` if the entry is not found.
    """
    try:
        unit = getattr(__import__('refinery', None, None, [name]), name, None)
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
    import shlex
    module, *arguments = shlex.split(command)
    return load(module, *arguments)
