from __future__ import annotations

import codecs

from refinery.lib.dotnet.resources import NetStructuredResources, NoManagedResource
from refinery.lib.types import Param, asbuffer
from refinery.units import RefineryPartialResult
from refinery.units.formats import Arg, PathExtractorUnit, UnpackResult


class dnmr(PathExtractorUnit):
    """
    Extracts subfiles from .NET managed resources. Parses serialized ResourceManager streams
    embedded in .NET assemblies.
    """
    def __init__(
        self, *paths, path=b'name',
        raw: Param[bool, Arg.Switch('-w', help='Do not deserialize the managed resource entry data.')] = False,
        **kwargs
    ):
        super().__init__(*paths, path=path, raw=raw, **kwargs)

    def unpack(self, data):
        try:
            managed = NetStructuredResources(data)
        except NoManagedResource:
            managed = None
        if not managed:
            raise RefineryPartialResult('no managed resources found', partial=data)
        for entry in managed:
            if entry.Error:
                self.log_warn(F'entry {entry.Name} carried error message: {entry.Error}')
            data = entry.Data
            if not self.args.raw:
                if b := asbuffer(v := entry.Value):
                    data = b
                elif isinstance(v, str):
                    data = codecs.encode(v, self.codec)
            yield UnpackResult(entry.Name, data)

    @classmethod
    def handles(cls, data):
        return data[:4] == b'\xCE\xCA\xEF\xBE'
