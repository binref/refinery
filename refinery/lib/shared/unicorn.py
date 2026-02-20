from refinery.lib.shared import dependency
from refinery.lib.tools import NoLogging


@dependency('unicorn>=2.0.1.post1', ['default', 'extended'])
def unicorn():
    import importlib
    importlib.import_module('setuptools')
    with NoLogging():
        import unicorn
        import unicorn.unicorn
        return unicorn
