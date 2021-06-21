#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import arg, Unit
from ...lib.tools import isbuffer
from . import check_variable_name


class swap(Unit):
    """
    Swap the contents of an existing variable with the contents of the chunk. The variable
    has to contain a binary string.
    """
    def __init__(self, name: arg(type=str, metavar='name', help='The meta variable name.')):
        super().__init__(name=check_variable_name(name))

    def process(self, data):
        name = self.args.name
        try:
            meta = data.meta[name]
        except KeyError:
            meta = bytearray()
        if isinstance(meta, str):
            meta = meta.encode(self.codec)
        elif not isbuffer(meta):
            raise ValueError(F'Unable to swap data with variable {name} because it has type {type(meta).__name__}.')
        return self.labelled(meta, **{name: data})
