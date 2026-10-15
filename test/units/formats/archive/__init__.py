import contextlib

from unittest import mock


@contextlib.contextmanager
def failing_inno_function(name: str):
    """
    Emulates the Inno Setup function of the given name as one that raises an error.
    """
    from refinery.lib.inno.emulator import IFPSEmulatedFunction, IFPSEmulator
    from refinery.lib.inno.symbols import IFPSAPI

    def fail(*_):
        raise RuntimeError(F'{name} failed')

    declaration = IFPSAPI[name]
    handler = IFPSEmulatedFunction(fail, [False] * declaration.argc, declaration.void)
    with mock.patch.dict(IFPSEmulator.external_symbols[''], {name: handler}):
        yield
