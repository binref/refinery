from refinery.lib.shared import dependency


@dependency('pefile', ['default', 'extended'])
def pefile():
    import pefile
    return pefile
