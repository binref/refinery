#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generates the list of dependency categories.
"""
from __future__ import annotations

from refinery import __unit_loader__
from refinery import *

all_optional: set[str] = set()
all_required: set[str] = set()
extras: dict[str, set[str]] = {'all': all_optional}

with __unit_loader__:
    for executable in __unit_loader__.cache.values():
        if executable.optional_dependencies:
            for key, deps in executable.optional_dependencies.items():
                bucket = extras.setdefault(key, set())
                bucket.update(deps)
                all_optional.update(deps)
        if executable.required_dependencies:
            all_required.update(executable.required_dependencies)

for category, deps in extras.items():
    print(category)
    deps = list(deps)
    deps.sort()
    for dep in deps:
        print('\t', dep)
