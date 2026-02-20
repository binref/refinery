from refinery.lib.shared import dependency


@dependency('capstone', ['default', 'extended'])
def capstone():
    import capstone
    return capstone
