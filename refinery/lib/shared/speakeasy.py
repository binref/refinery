from refinery.lib.shared import dependency


@dependency('speakeasy-emulator-refined>=2.0', ['extended'])
def speakeasy():
    import speakeasy
    import speakeasy.profiler
    import speakeasy.windows.objman
    return speakeasy
