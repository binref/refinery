from refinery.lib.shared import dependency


@dependency('icicle-emu>=0.0.11', ['extended', 'all'])
def icicle():
    import icicle
    return icicle
