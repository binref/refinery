#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import arg, PathExtractorUnit, UnpackResult
from .....lib.tools import isbuffer
from .....lib.dotnet.resources import NetStructuredResources, NoManagedResource


class dnmr(PathExtractorUnit):
    """
    Extracts subfiles from .NET managed resources.
    """
    def __init__(
        self, *paths, list=False, join=False,
        raw: arg.switch('-r', help='Do not deserialize the managed resource entry data.') = False
    ):
        super().__init__(*paths, list=list, join=join)
        self.args.raw = raw

    def unpack(self, data):
        try:
            managed = NetStructuredResources(data)
        except NoManagedResource:
            managed = None
        if not managed:
            raise ValueError('no managed resources found.')
        for entry in managed:
            if entry.Error:
                self.log_warn(F'entry {entry.Name} carried error message: {entry.Error}')
            yield UnpackResult(entry.Name,
                entry.Value if not self.args.raw and isbuffer(entry.Value) else entry.Data)
