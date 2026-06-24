from importlib.metadata import PackageNotFoundError, version

from refinery.lib.shared import dependency

# The Speakeasy backend (refinery/lib/emulator/se.py) reaches into Speakeasy internals that have
# no public-facade equivalent and that change between versions; it is validated only against the
# version pinned here. Bumping it requires re-checking and re-testing that backend.
_SUPPORTED_SPEAKEASY = '2.0.0b3'


@dependency(F'speakeasy-emulator=={_SUPPORTED_SPEAKEASY}', 3)
def speakeasy():
    import speakeasy
    import speakeasy.profiler
    import speakeasy.winenv.defs.registry.reg
    import speakeasy.windows.objman
    try:
        installed = version('speakeasy-emulator')
    except PackageNotFoundError:
        installed = None
    if installed not in (None, _SUPPORTED_SPEAKEASY):
        raise RuntimeError(
            F'The Speakeasy emulator backend is validated only against speakeasy-emulator '
            F'{_SUPPORTED_SPEAKEASY}, but {installed} is installed. The backend depends on '
            F'Speakeasy internals that change between versions; update '
            F'refinery/lib/emulator/se.py and re-pin this version after testing.')
    return speakeasy
