#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units.formats import Arg, PathExtractorUnit, UnpackResult
from refinery.units import RefineryPartialResult
from refinery.lib.tools import isbuffer
from refinery.lib.dotnet.resources import NetStructuredResources, NoManagedResource


class dnmr(PathExtractorUnit):
    """
    Extracts subfiles from .NET managed resources.
    """
    def __init__(
        self, *paths, list=False, join_path=False, drop_path=False, exact=False, fuzzy=0, regex=False, path=b'name',
        raw: Arg.Switch('-w', help='Do not deserialize the managed resource entry data.') = False
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
                if isinstance(entry.Value, str):
                    data = entry.Value.encode('utf-16le')
                elif isbuffer(entry.Value):
                    data = entry.Value
            yield UnpackResult(entry.Name, data)
