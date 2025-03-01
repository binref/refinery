from __future__ import annotations

from typing import Type, Dict, Any

import importlib
import functools

from .. import refinery, TestBase, NameUnknownException
from refinery.units import requirement, RefineryImportMissing, Entry, LogLevel

__all__ = ['refinery', 'TestUnitBase', 'NameUnknownException']


class MissingRequirement(property):

    def __init__(self, name):
        def broken(*a, **k):
            raise RefineryImportMissing(name)
        super().__init__(broken)
        self.name = name

    def __get__(self, unit, tp=None):
        raise RefineryImportMissing(self.name)


class TestUnitBaseMeta(type):

    def __init__(cls: TestUnitBase, name, bases, namespace: Dict[str, Any]):
        try:
            unit = cls.unit()
            has_optional_imports = bool(unit.optional_dependencies)
        except Exception:
            has_optional_imports = False
        if has_optional_imports:
            assert unit
            for name, method in namespace.items():
                if not name.startswith('test_'):
                    continue
                if not callable(method):
                    continue
                @functools.wraps(method) # noqa
                def wrapped_method(self: TestUnitBase, *args, __wrapped_method=method, **kwargs):
                    r = __wrapped_method(self, *args, **kwargs)
                    restoration = {}
                    for base in unit.mro():
                        for name, getter in base.__dict__.items():
                            if name in restoration:
                                continue
                            if isinstance(getter, requirement):
                                restoration[name] = getter
                                setattr(unit, name, MissingRequirement(name))
                    try:
                        r = __wrapped_method(self, *args, **kwargs)
                    except ImportError:
                        pass
                    finally:
                        for name, getter in restoration.items():
                            setattr(unit, name, getter)
                    return r
                setattr(cls, name, wrapped_method)
                namespace[name] = wrapped_method

        return type.__init__(cls, name, bases, namespace)


class TestUnitBase(TestBase, metaclass=TestUnitBaseMeta):

    @staticmethod
    def _relative_module_path(path: str, strip_test=True):
        path = path.split('.')
        path = path[1:]
        if strip_test:
            path = [x[4:].lstrip('_-.') if x.startswith('test') else x for x in path]
        return '.'.join(path)

    @classmethod
    def unit(cls) -> Type[refinery.Unit]:
        name = cls._relative_module_path(cls.__module__)
        try:
            module = importlib.import_module(F'refinery.{name}')
        except ImportError:
            pass
        else:
            for object in vars(module).values():
                if isinstance(object, type) and issubclass(object, Entry) and object.__module__ == name:
                    return object
        try:
            basename = name.rsplit('.', 1)[-1]
            entry = getattr(refinery, basename)
        except AttributeError:
            from refinery.lib.loader import get_all_entry_points
            for entry in get_all_entry_points():
                if entry.__name__ == name:
                    break
                if cls._relative_module_path(entry.__module__) == name:
                    break
            else:
                raise NameUnknownException(name)
        return entry

    @classmethod
    def load(cls, *args, **kwargs) -> refinery.Unit:
        unit = cls.unit().assemble(*args, **kwargs)
        unit.log_level = LogLevel.DETACHED
        return unit
