from refinery.lib.shared import dependency


@dependency('capstone', 1)
def capstone():
    import capstone
    return capstone
