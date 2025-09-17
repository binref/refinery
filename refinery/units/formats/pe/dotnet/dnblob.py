from __future__ import annotations

from refinery.lib.dotnet.header import DotNetHeader
from refinery.units import Unit


class dnblob(Unit):
    """
    Extracts all blobs defined in the `#Blob` stream of .NET executables.
    """
    def process(self, data):
        header = DotNetHeader(data, parse_resources=False)
        yield from header.meta.Streams.Blob.values()

    @classmethod
    def handles(cls, data):
        from refinery.lib.id import is_likely_pe_dotnet
        return is_likely_pe_dotnet(data)
