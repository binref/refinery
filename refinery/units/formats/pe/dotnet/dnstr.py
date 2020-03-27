#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .... import arg, Unit
from .....lib.dotnet.header import DotNetHeader


class dnstr(Unit):
    """
    Extracts all strings defined in the `#Strings` and `#US` streams of .NET
    executables.
    """

    def __init__(
        self,
        user: arg.switch('-m', '--meta', off=True, group='HEAP', help='Only extract from #Strings.') = True,
        meta: arg.switch('-u', '--user', off=True, group='HEAP', help='Only extract from #US.') = True,
    ):
        if not meta and not user:
            raise ValueError('Either ascii or utf16 strings must be enabled.')
        super().__init__(meta=meta, user=user)

    def process(self, data):
        header = DotNetHeader(data, parse_resources=False)
        if self.args.meta:
            for string in header.meta.Streams.Strings.values():
                yield string.encode(self.codec)
        if self.args.user:
            for string in header.meta.Streams.US.values():
                yield string.encode(self.codec)
