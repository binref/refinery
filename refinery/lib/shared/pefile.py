from refinery.lib.shared import dependency


@dependency('pefile', 1)
def pefile():
    import pefile
    return pefile
