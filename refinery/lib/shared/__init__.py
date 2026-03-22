"""
Shared dependencies. Each shared dependency is stored in a submodule.
"""
from __future__ import annotations

from typing import Callable

from refinery.lib.dependencies import LazyDependency, Mod
from refinery.units import Unit


class GlobalDependenciesDummy(Unit, abstract=True):
    """
    The sole purpose of this unit is to collect shared dependencies.
    """


def dependency(name: str, level: int = 0, more: str | None = None):
    """
    This decorator is used to install a shared dependency.
    """
    def decorator(imp: Callable[[], Mod]):
        dep = LazyDependency(imp, name, level, more)
        dep.register(GlobalDependenciesDummy)
        return dep()
    return decorator
