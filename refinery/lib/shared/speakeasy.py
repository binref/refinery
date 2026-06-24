from refinery.lib.shared import dependency


@dependency('speakeasy-emulator==2.0.0b3', 3)
def speakeasy():
    import speakeasy
    import speakeasy.profiler
    import speakeasy.winenv.defs.registry.reg
    import speakeasy.windows.objman
    return speakeasy
