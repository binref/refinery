from refinery.lib.shared import dependency


@dependency('orjson', 1)
def orjson():
    import orjson
    return orjson
