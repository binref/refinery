import importlib

from .. import refinery, TestBase, NameUnknownException

__all__ = ['refinery', 'TestUnitBase', 'NameUnknownException']


class TestUnitBase(TestBase):

    def _relative_module_path(self, path, strip_test=True):
        path = path.split('.')
        path = path[1:]
        if strip_test:
            path = [x[4:].lstrip('_-.') if x.startswith('test') else x for x in path]
        return '.'.join(path)

    def load(self, *args, **kwargs) -> refinery.Unit:
        name = self._relative_module_path(self.__class__.__module__)
        try:
            module = importlib.import_module(F'refinery.{name}')
        except ImportError:
            pass
        else:
            for object in vars(module).values():
                if isinstance(object, type) and issubclass(object, refinery.units.Entry) and object.__module__ == name:
                    return object
        try:
            basename = name.rsplit('.', 1)[-1]
            entry = getattr(refinery, basename)
        except AttributeError:
            from refinery.lib.loader import get_all_entry_points
            for entry in get_all_entry_points():
                if entry.__name__ == name:
                    break
                if self._relative_module_path(entry.__module__) == name:
                    break
            else:
                raise NameUnknownException(name)
        unit = entry.assemble(*args, **kwargs)
        unit.log_level = refinery.units.LogLevel.DETACHED
        return unit
