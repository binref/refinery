#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import JSONEncoderUnit
from .....lib.dotnet.header import DotNetHeader


class dnhdr(JSONEncoderUnit):
    """
    Expects data that has been formatted with the `BinaryFormatter` class. The
    output is a representation of the deserialized data in JSON format.
    """

    @classmethod
    def interface(cls, argp):
        argp.add_argument(
            '-r', '--resources',
            action='store_true',
            help='also parse resources'
        )
        return super().interface(argp)

    def process(self, data):
        dn = DotNetHeader(data, parse_resources=self.args.resources)
        dn = {
            'Head': dn.head,
            'Meta': dn.meta
        }

        if self.args.resources:
            dn['RSRC'] = dn.resources

        return self.to_json(dn)
