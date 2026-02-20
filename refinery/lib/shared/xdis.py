from refinery.lib.shared import dependency


@dependency('xdis', ['arc', 'python', 'extended'])
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
