#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from refinery.units import Unit
from refinery.lib.dotnet.header import DotNetHeader


class dnblob(Unit):
    """
    Extracts all blobs defined in the `#Blob` stream of .NET executables.
    """
    def process(self, data):
        header = DotNetHeader(data, parse_resources=False)
        for blob in header.meta.Streams.Blob.values():
            yield blob

    @classmethod
    def handles(cls, data):
        from refinery.lib.id import is_likely_pe_dotnet
        return is_likely_pe_dotnet(data)
