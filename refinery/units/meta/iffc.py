from __future__ import annotations

from refinery.lib.types import INF, Param
from refinery.units.meta import Arg, ConditionalUnit


class iffc(ConditionalUnit, docs='{0}{p}{1}'):
    """
    Filter incoming chunks depending on whether their size is within any of the given bounds.
    """
    def __init__(
        self,
        *bounds: Param[slice, Arg.Bounds(help='Specifies an (inclusive) range to check for.', intok=True)],
        retain=False,
    ):
        if not bounds:
            raise ValueError('cannot filter for size without specifying any bounds')
        super().__init__(
            bounds=bounds,
            retain=retain,
        )

    def match(self, chunk):
        length: int = len(chunk)
        for bounds in self.args.bounds:
            if isinstance(bounds, int):
                if length == bounds:
                    return True
            if isinstance(bounds, slice):
                a = bounds.start or 0
                b = bounds.stop or INF
                t = bounds.step or 1
                if a <= length <= b and not (length - a) % t:
                    return True
        return False
