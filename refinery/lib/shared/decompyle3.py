from refinery.lib.shared import dependency


@dependency('decompyle3', 2)
def decompyle3():
    import decompyle3
    import decompyle3.main
    return decompyle3
