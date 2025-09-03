from __future__ import annotations

from refinery.units import Arg
from refinery.units.formats.pe.dotnet import DotNetJSONEncoderUnit
from refinery.lib.dotnet.deserialize import BinaryFormatterParser


class dnds(DotNetJSONEncoderUnit):
    """
    Stands for "DotNet DeSerialize": Expects data that has been serialized using the .NET class
    "BinaryFormatter". The output is a representation of the deserialized data in JSON format.
    """

    def __init__(
        self,
        dereference: Arg.Switch('-r', '--keep-references', off=True,
            help='Do not resolve Object references in serialized data.') = True,
        encode=None, digest=None, arrays=False
    ):
        super().__init__(encode=encode, digest=digest, arrays=arrays, dereference=dereference)

    def process(self, data):
        self.log_debug('initializing parser, will fail on malformed stream')
        bf = BinaryFormatterParser(
            data,
            keep_meta=True,
            dereference=self.args.dereference,
            ignore_errors=not self.log_debug(),
        )

        return self.to_json([
            {
                'Type': repr(record),
                'Data': record
            } for record in bf
        ])
