from __future__ import annotations

from refinery.lib.dotnet.header import DotNetHeader
from refinery.lib.structures import struct_to_json
from refinery.lib.types import Param
from refinery.units import Arg
from refinery.units.formats import JSONEncoderUnit


class dnhdr(JSONEncoderUnit):
    """
    Expects data that has been formatted with the `BinaryFormatter` class. The
    output is a representation of the deserialized data in JSON format.
    """
    def __init__(
        self,
        resources: Param[bool, Arg.Switch('-r', '--resources', help='Also parse .NET resources.')] = False,
        encode=None, digest=None, arrays=False,
    ):
        super().__init__(encode=encode, digest=digest, arrays=arrays, resources=resources)

    def process(self, data):
        dn = DotNetHeader(data, parse_resources=self.args.resources)
        result = {
            'Head': struct_to_json(dn.head),
            'Meta': struct_to_json(dn.meta),
        }
        if self.args.resources:
            result['RSRC'] = struct_to_json(dn.resources)
        return self.to_json(result)

    @classmethod
    def handles(cls, data):
        from refinery.lib.id import is_likely_pe_dotnet
        return is_likely_pe_dotnet(data)
