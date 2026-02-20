from refinery.lib.shared import dependency


@dependency('pyppmd', ['arc', 'extended'])
def pyppmd():
    import pyppmd
    return pyppmd
