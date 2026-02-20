from refinery.lib.shared import dependency


@dependency('uncompyle6>=3.9.3', ['arc', 'python', 'extended'])
def uncompyle6():
    import uncompyle6
    import uncompyle6.main
    return uncompyle6
