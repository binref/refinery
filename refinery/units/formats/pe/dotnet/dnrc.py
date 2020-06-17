#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import PathExtractorUnit, UnpackResult
from .....lib.dotnet.header import DotNetHeader


class dnrc(PathExtractorUnit):
    """
    Extracts all .NET resources whose name matches any of the given patterns
    and outputs them. Use the `refinery.units.formats.pe.dotnet.dnmr` unit to
    extract subfiles from managed .NET resources.
    """
    def unpack(self, data):
        header = DotNetHeader(data)

        if not header.resources:
            if self.args.list:
                return
            raise ValueError('This file contains no resources.')

        for resource in header.resources:
            yield UnpackResult(resource.Name, resource.Data)
