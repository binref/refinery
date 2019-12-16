#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Functions to help dynamically load refinery units.
"""
import pkgutil
import pkg_resources


def get_package_name():
    """
    Retrieves the toplevel package name.
    """
    root = __name__
    first_dot = root.find('.')
    if first_dot > 0:
        root = root[:first_dot]
    return root


def get_all_entry_points():
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


def get_entry_point(name: str):
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
            raise AttributeError('no entry point with name "%s" was found.' % name)
    return entry


def load(name: str, *args, **kwargs):
    """
    Loads the unit specified by `name`, initialized with the given arguments
    and keyword arguments.
    """
    entry = get_entry_point(name)
    return entry(*args, **kwargs)


def load_commandline(command: str):
    """
    Returns a unit as it would be loaded from a given command line string.
    """
    import shlex
    module, *arguments = shlex.split(command)
    return load(module, *arguments)
