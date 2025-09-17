from __future__ import annotations

from refinery.lib.types import Param, buf
from refinery.units import Arg, Chunk, Unit


class push(Unit):
    """
    The unit inserts an additional chunk before each input chunk and moves the original
    data out of scope. This chunk is considered the "original" data, while the one inserted
    in front of it is used as an intermediate result. By default, this intermediate data is
    a copy of the input data. For example:

        emit key=value | push [[| rex =(.*)$ {1} | pop v ]| repl var:v censored ]

    will output `key=censored`. The application of `refinery.rex` turns the (duplicated)
    data into just the value, which is then stored in the variable `v`. The application
    of `refinery.repl` replaces this value with the hard-coded string `censored`.
    """
    def __init__(self, data: Param[buf, Arg(help='The data to be pushed, by default a copy of the input.')] = B''):
        super().__init__(data=data)

    def process(self, data: Chunk):
        src = self.args.data
        tos = data.copy(meta=True, data=False)
        tos[:] = src or data
        if self.args.nesting > 0:
            data.set_next_scope(False)
        else:
            try:
                data.visible = False
            except AttributeError:
                self.log_warn('application has no effect outside frame.')
        yield data
        yield tos
