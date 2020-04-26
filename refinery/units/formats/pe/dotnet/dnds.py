#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import arg, JSONEncoderUnit
from .....lib.dotnet.deserialize import BinaryFormatterParser


class dnds(JSONEncoderUnit):
    """
    Expects data that has been formatted with the .NET class `BinaryFormatter`.
    The output is a representation of the deserialized data in JSON format.
    """

    def __init__(
        self, dereference: arg.switch('-r', '--keep-references', off=True,
            help='Do not resolve Object references in serialized data.') = True,
        encode=None, digest=None
    ):
        super().__init__(encode=encode, digest=digest, dereference=dereference)

    def process(self, data):
        self.log_debug('initializing parser, will fail on malformed stream')
        bf = BinaryFormatterParser(
            data,
            keep_meta=True,
            dereference=self.args.dereference,
            ignore_errors=not self.log_debug(),
        )

        return self.to_json([
            {
                'Type': repr(record),
                'Data': record
            } for record in bf
        ])
