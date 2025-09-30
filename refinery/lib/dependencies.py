from __future__ import annotations

from typing import TYPE_CHECKING, Callable, Collection, Generic, TypeVar, cast

from refinery.lib.exceptions import RefineryImportError, RefineryImportMissing

if TYPE_CHECKING:
    from refinery.units import Unit

Mod = TypeVar('Mod')


class MissingModule:
    """
    This class can wrap a module import that is currently missing. If any attribute of the missing
    module is accessed, it raises `refinery.units.RefineryImportMissing`.
    """
    def __init__(self, name, install=None, info=None, error=None):
        self.name = name
        self.install = install or [name]
        self.info = info
        self.error = error

    def __getattr__(self, key: str):
        if key.startswith('__') and key.endswith('__'):
            raise AttributeError(key)
        if (error := self.error) and isinstance(error, RefineryImportError):
            raise error
        raise RefineryImportMissing(self.name, self.install, info=self.info)


class LazyDependency(Generic[Mod]):
    """
    A lazily evaluated dependency. Functions decorated with `refinery.lib.dependencies.dependency`
    are converted into this type. Calling the object returns either the return value of that
    function, which should be an imported module, or a `refinery.lib.dependencies.MissingModule`
    wrapper which will raise a `refinery.lib.exceptions.RefineryImportMissing` exception as soon
    as any of its members is accessed.
    """
    _mod: Mod | None
    _imp: Callable[[], Mod]
    name: str
    dist: Collection[str]
    info: str | None

    __slots__ = (
        '_mod',
        '_imp',
        '_who',
        'name',
        'dist',
        'info',
    )

    def __init__(self, imp: Callable[[], Mod], name: str, dist: Collection[str], info: str | None):
        self.name = name
        self.dist = dist
        self.info = info
        self._imp = imp
        self._mod = None
        self._who: set[type[Unit]] = set()

    def register(self, unit: type[Unit] | None):
        if unit is None:
            return None
        if unit in (units := self._who):
            return unit
        if dist := self.dist:
            optmap = unit.optional_dependencies
            if optmap is None:
                unit.optional_dependencies = optmap = {}
            buckets = [optmap.setdefault(name, set()) for name in dist]
        else:
            bucket = unit.required_dependencies
            if bucket is None:
                unit.required_dependencies = bucket = set()
            buckets = [bucket]
        for bucket in buckets:
            bucket.add(self.name)
        units.add(unit)
        return unit

    def __call__(self) -> Mod:
        if (mod := self._mod) is None:
            try:
                mod = self._imp()
            except ImportError as error:
                install = {self.name}
                for unit in self._who:
                    if deps := unit.optional_dependencies:
                        for v in deps.values():
                            install.update(v)
                mod = cast(Mod, MissingModule(
                    self.name, install=install, info=self.info, error=error))
            self._mod = mod
        return mod


class DependencyAccessor(Generic[Mod]):
    """
    Methods decorated with `refinery.lib.dependencies.dependency_accessor` turn into objects of
    this type. See the description of this decorator for more details.
    """
    def __init__(self, dependency: LazyDependency[Mod]):
        self.dependency = dependency
        self.parent = None
        self.module = None

    def __get__(self, _: Unit | None, unit: type[Unit] | None = None):
        if (mod := self.module) is None:
            if unit is None:
                unit = self.parent
            dependency = self.dependency
            dependency.register(unit)
            self.module = mod = dependency()
        return mod

    def __set_name__(self, unit: type[Unit], name: str):
        self.parent = unit
        self.dependency.register(unit)


def dependency(name: str, dist: Collection[str] = (), info: str | None = None, local: bool = False):
    """
    A decorator to mark up an optional dependency. The decorated function can import the module
    and return the module object. The `name` argument of the decorator specifies the name of the
    dependency, while `dist` specifies a sequence of extra buckets at which this dependency will
    automatically be installed by the refinery setup. Functions that are decorated with this
    method will turn into a `refinery.lib.dependencies.LazyDependency`.
    """
    def decorator(imp: Callable[[], Mod]):
        return LazyDependency(imp, name, dist, info)
    return decorator


def dependency_accessor(name: str, dist: Collection[str] = (), info: str | None = None):
    """
    The same description as for `refinery.lib.dependencies.dependency` applies here, except that
    this decorator is used to decorate static class methods which then turn into a property-like
    accessor of type `refinery.lib.dependencies.DependencyAccessor`. Consider, for example, a code
    excerpt from `refinery.units.compression.brotli.brotli`:

        class brotli(Unit):
            @Unit.Requires('brotlipy', ['all'])
            def _brotli():
                import brotli
                return brotli

            def process(self, data):
                return self._brotli.decompress(bytes(data))

    The `brotli` dependency is installed only when refinery is installed with the `all` extra.
    """
    def decorator(imp: Callable[[], Mod]):
        return DependencyAccessor(LazyDependency(imp, name, dist, info))
    return decorator
