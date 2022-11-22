#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units import Unit, Chunk, Arg
from refinery.lib.meta import metavars


class mvc(Unit):
    """
    Removes meta variables that were created in the current frame. If no variable names are given,
    the unit removes all meta variables that were created in the current frame. Note that this can
    recover variables from outer frames that were previously shadowed.
    """
    def __init__(self, *names: Arg(type=str, metavar='name', help='Name of a variable to be removed.')):
        super().__init__(names=names)

    def process(self, data: Chunk):
        meta = metavars(data)
        keys = self.args.names or list(meta.variable_names())
        for key in keys:
            meta.discard(key)
        return data
