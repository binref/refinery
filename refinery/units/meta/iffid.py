from __future__ import annotations

from refinery.lib.types import Param
from refinery.units import Arg
from refinery.units.meta import ConditionalUnit
from refinery.lib.id import Fmt, get_structured_data_type


class iffid(ConditionalUnit, docs='{0}{p}{1}'):
    """
    Filter incoming chunks by discarding those that do not identify as a given file type.
    """
    def __init__(
        self,
        pattern: Param[str, Arg.Option(choices=Fmt, metavar='filetype',
            help='Specify a known file type name: {choices}')],
        retain: bool = False
    ):
        super().__init__(pattern=Arg.AsOption(pattern, Fmt), retain=retain)

    def match(self, chunk):
        return self.args.pattern == get_structured_data_type(chunk)
