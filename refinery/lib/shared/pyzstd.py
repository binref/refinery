from refinery.lib.shared import dependency


@dependency('pyzstd', ['arc', 'extended'])
def pyzstd():
    import pyzstd
    return pyzstd
