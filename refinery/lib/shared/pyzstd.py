from refinery.lib.shared import dependency


@dependency('pyzstd', 2)
def pyzstd():
    import pyzstd
    return pyzstd
