#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units import Arg, Unit, Chunk
from refinery.lib.meta import metavars


class mvc(Unit):
    """
    Clean up meta variables in the current scope that are older than a given value.
    """
    def __init__(self, age: Arg.Number(
        help='The maximum number of steps that the variable may have existed; the default is {default}.') = 1
    ):
        super().__init__(age=age)

    def process(self, data: Chunk):
        meta = metavars(data)
        scope = data.scope
        age = self.args.age
        for key in list(meta.keys()):
            if meta.get_scope(key, scope) < scope:
                continue
            if meta.get_age(key) > age:
                meta.discard(key)
        return data
