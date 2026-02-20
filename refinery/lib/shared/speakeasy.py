from refinery.lib.shared import dependency


@dependency('speakeasy-emulator-refined==1.6.1b0.post3', ['extended'])
def speakeasy():
    import speakeasy
    import speakeasy.profiler
    import speakeasy.windows.objman
    return speakeasy
