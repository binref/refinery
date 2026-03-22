from refinery.lib.shared import dependency


@dependency('pyppmd', 2)
def pyppmd():
    import pyppmd
    return pyppmd
