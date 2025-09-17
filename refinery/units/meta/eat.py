from __future__ import annotations

from refinery.lib.meta import check_variable_name, metavars
from refinery.lib.tools import isbuffer
from refinery.lib.types import Param
from refinery.units import Arg, Chunk, Unit


class eat(Unit):
    """
    Consume a meta variable and replace the contents of the current chunk with it. If the variable
    contains a string, it is encoded with the default codec. If the variable cannot be converted to
    a byte string, the data is lost and an empty chunk is returned.
    """
    def __init__(
        self,
        name: Param[str, Arg.String(help='The name of the variable to be used.')],
    ):
        super().__init__(name=check_variable_name(name))

    def process(self, data: Chunk):
        def invalid_type():
            return F'variable {name} is of type "{type}", unable to convert to byte string - data is lost'
        name = self.args.name
        meta = metavars(data)
        data = meta.pop(name)
        type = data.__class__.__name__
        if isinstance(data, int):
            self.log_info(F'variable {name} is an integer, converting to string.')
            data = str(data).encode(self.codec)
        if isinstance(data, str):
            self.log_info(F'variable {name} is a string, encoding as {self.codec}')
            data = data.encode(self.codec)
        elif not isbuffer(data):
            try:
                wrapped = bytearray(data)
            except Exception:
                self.log_warn(invalid_type())
                data = None
            else:
                data = wrapped
        return data
