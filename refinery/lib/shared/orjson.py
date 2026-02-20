from refinery.lib.shared import dependency


@dependency('orjson', ['speed', 'default', 'extended'])
def orjson():
    import orjson
    return orjson
