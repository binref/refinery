#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from refinery.units import Arg
from refinery.units.formats.pe.dotnet import DotNetJSONEncoderUnit
from refinery.lib.dotnet.header import DotNetHeader


class dnhdr(DotNetJSONEncoderUnit):
    """
    Expects data that has been formatted with the `BinaryFormatter` class. The
    output is a representation of the deserialized data in JSON format.
    """
    def __init__(
        self,
        resources: Arg.Switch('-r', '--resources', help='Also parse .NET resources.') = False,
        encode=None, digest=None, arrays=False,
    ):
        super().__init__(encode=encode, digest=digest, arrays=arrays, resources=resources)

    def process(self, data):
        dn = DotNetHeader(data, parse_resources=self.args.resources)
        dn = {
            'Head': dn.head,
            'Meta': dn.meta
        }

        if self.args.resources:
            dn['RSRC'] = dn.resources

        return self.to_json(dn)

    @classmethod
    def handles(cls, data):
        from refinery.lib.id import is_likely_pe_dotnet
        return is_likely_pe_dotnet(data)
