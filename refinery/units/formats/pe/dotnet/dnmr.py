from __future__ import annotations

import codecs

from refinery.lib.dotnet.resources import NetStructuredResources, NoManagedResource
from refinery.lib.tools import asbuffer
from refinery.lib.types import Param
from refinery.units import RefineryPartialResult
from refinery.units.formats import Arg, PathExtractorUnit, UnpackResult


class dnmr(PathExtractorUnit):
    """
    Extracts subfiles from .NET managed resources.
    """
    def __init__(
        self, *paths, list=False, join_path=False, drop_path=False, exact=False, fuzzy=0, regex=False, path=b'name',
        raw: Param[bool, Arg.Switch('-w', help='Do not deserialize the managed resource entry data.')] = False
    ):
        super().__init__(
            *paths,
            list=list,
            join_path=join_path,
            drop_path=drop_path,
            path=path,
            raw=raw,
            fuzzy=fuzzy,
            exact=exact,
            regex=regex,
        )

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
