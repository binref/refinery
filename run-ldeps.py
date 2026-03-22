#!/usr/bin/env python3
"""
Generates the list of dependency categories.
"""
from __future__ import annotations

import builtins
import importlib
import itertools
import pkgutil

from refinery import __unit_loader__

import refinery
import refinery.lib.shared

deps_by_level: dict[int, set[str]] = {}
all_required: set[str] = set()

for _, name, _ in pkgutil.iter_modules(refinery.lib.shared.__path__):
    # populate all shared dependencies
    importlib.import_module(F'refinery.lib.shared.{name}')

with __unit_loader__ as ldr:
    ldr.reload()
    for executable in itertools.chain(
        (refinery.lib.shared.GlobalDependenciesDummy,),
        __unit_loader__.cache.values()
    ):
        if executable.optional_dependencies:
            for level, deps in executable.optional_dependencies.items():
                bucket = deps_by_level.setdefault(level, set())
                bucket.update(deps)
        if executable.required_dependencies:
            bucket = deps_by_level.setdefault(0, set())
            bucket.update(executable.required_dependencies)

for level in builtins.sorted(deps_by_level):
    print(F'Dependencies Level {level}:')
    deps = builtins.sorted(deps_by_level[level])
    for dep in deps:
        print(' ', dep)
