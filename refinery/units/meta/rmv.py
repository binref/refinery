from __future__ import annotations

from refinery.lib.meta import metavars
from refinery.lib.types import Param
from refinery.units import Arg, Chunk, Unit


class rmv(Unit):
    """
    Short for "ReMove Variable": Removes meta variables that were created in the current frame. If no
    variable names are given, the unit removes all of them. Note that this can recover variables from
    outer frames that were previously shadowed.
    """
    def __init__(self, *names: Param[str, Arg.String(metavar='name', help='Name of a variable to be removed.')]):
        super().__init__(names=names)

    def process(self, data: Chunk):
        meta = metavars(data)
        keys = self.args.names or list(meta.variable_names())
        for key in keys:
            meta.discard(key)
        return data
