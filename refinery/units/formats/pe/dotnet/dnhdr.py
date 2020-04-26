#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import arg, JSONEncoderUnit
from .....lib.dotnet.header import DotNetHeader


class dnhdr(JSONEncoderUnit):
    """
    Expects data that has been formatted with the `BinaryFormatter` class. The
    output is a representation of the deserialized data in JSON format.
    """
    def __init__(
        self,
        resources: arg.switch('-r', '--resources', help='Also parse .NET resources.') = False,
        encode=None, digest=None
    ):
        super().__init__(encode=encode, digest=digest, resources=resources)

    def process(self, data):
        dn = DotNetHeader(data, parse_resources=self.args.resources)
        dn = {
            'Head': dn.head,
            'Meta': dn.meta
        }

        if self.args.resources:
            dn['RSRC'] = dn.resources

        return self.to_json(dn)
