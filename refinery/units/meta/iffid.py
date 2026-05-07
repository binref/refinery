from __future__ import annotations

from refinery.lib.id import Fmt, get_structured_data_type
from refinery.lib.types import Param
from refinery.units import Arg
from refinery.units.meta import ConditionalUnit


class iffid(ConditionalUnit, docs='{0}{p}{1}'):
    """
    Filter incoming chunks and keep only those that match one of the given file types.
    """
    def __init__(
        self,
        *pattern: Param[str, Arg.Option(choices=Fmt, metavar='filetype',
            help='Specify a known file type name: {choices}')],
        retain: bool = False
    ):
        super().__init__(
            pattern=[Arg.AsOption(p, Fmt) for p in pattern], retain=retain)

    def match(self, chunk):
        if t := get_structured_data_type(chunk):
            pattern: list[Fmt] = self.args.pattern
            self.log_info(F'computed: {t!s}')
            self.log_debug(F'expected: {pattern!s}')
            return any(p <= t for p in pattern)
        else:
            return False
