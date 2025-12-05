"""
Shared dependencies.
"""
from __future__ import annotations

from typing import Callable, Collection

from refinery.lib.dependencies import LazyDependency, Mod
from refinery.lib.tools import NoLogging
from refinery.units import Unit


class GlobalDependenciesDummy(Unit, abstract=True):
    """
    The sole purpose of this unit is to collect shared dependencies.
    """


def __global_dependency(name: str, dist: Collection[str] = (), more: str | None = None):
    def decorator(imp: Callable[[], Mod]):
        dep = LazyDependency(imp, name, dist, more)
        dep.register(GlobalDependenciesDummy)
        return dep()
    return decorator


@__global_dependency('capstone', ['default', 'extended'])
def capstone():
    import capstone
    return capstone


@__global_dependency('unicorn>=2.0.1.post1', ['default', 'extended'])
def unicorn():
    import importlib
    importlib.import_module('setuptools')
    with NoLogging():
        import unicorn
        import unicorn.unicorn
        return unicorn


@__global_dependency('speakeasy-emulator-refined==1.6.1b0.post3', ['extended'])
def speakeasy():
    import speakeasy
    import speakeasy.profiler
    import speakeasy.windows.objman
    return speakeasy


@__global_dependency('icicle-emu>=0.0.11', ['extended', 'all'])
def icicle():
    import icicle
    return icicle


@__global_dependency('xdis', ['arc', 'python', 'extended'])
def xdis():
    import sys

    import xdis
    import xdis.load
    import xdis.magics
    import xdis.marsh
    import xdis.op_imports
    import xdis.version_info
    A, B, C, *_ = sys.version_info
    version = F'{A}.{B}.{C}'
    canonic = F'{A}.{B}'
    if version not in xdis.magics.canonic_python_version:
        import importlib.util
        magic = importlib.util.MAGIC_NUMBER
        xdis.magics.add_magic_from_int(xdis.magics.magic2int(magic), version)
        xdis.magics.by_magic.setdefault(magic, set()).add(version)
        xdis.magics.by_version[version] = magic
        xdis.magics.magics[canonic] = magic
        xdis.magics.canonic_python_version[canonic] = canonic
        xdis.magics.add_canonic_versions(version, canonic)
        xdis.op_imports.op_imports.setdefault(canonic,
            next(iter(reversed(xdis.op_imports.op_imports.values()))))
    del A, B, C, version
    import xdis.std
    return xdis


@__global_dependency('uncompyle6>=3.9.3', ['arc', 'python', 'extended'])
def uncompyle6():
    import uncompyle6
    import uncompyle6.main
    return uncompyle6


@__global_dependency('decompyle3', ['arc', 'python'])
def decompyle3():
    import decompyle3
    import decompyle3.main
    return decompyle3


@__global_dependency('smda<2.0', ['all'])
def smda():
    import datetime
    datetime.UTC = datetime.timezone.utc
    import smda
    import smda.Disassembler
    import smda.DisassemblyResult
    return smda


@__global_dependency('orjson', ['speed', 'default', 'extended'])
def orjson():
    import orjson
    return orjson


@__global_dependency('pefile', ['default', 'extended'])
def pefile():
    import pefile
    return pefile


@__global_dependency('pyppmd', ['arc', 'extended'])
def pyppmd():
    import pyppmd
    return pyppmd


@__global_dependency('pyzstd', ['arc', 'extended'])
def pyzstd():
    import pyzstd
    return pyzstd
