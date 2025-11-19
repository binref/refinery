from __future__ import annotations

from refinery.lib.dotnet.header import DotNetHeader
from refinery.units.formats import PathExtractorUnit, UnpackResult


class dnrc(PathExtractorUnit):
    """
    Extracts all .NET resources whose name matches any of the given patterns
    and outputs them. Use the `refinery.units.formats.pe.dotnet.dnmr` unit to
    extract subfiles from managed .NET resources.
    """
    def unpack(self, data):
        for resource in DotNetHeader(data).resources:
            yield UnpackResult(resource.Name, resource.Data)

    @classmethod
    def handles(cls, data):
        from refinery.lib.id import is_likely_pe_dotnet
        return is_likely_pe_dotnet(data)
