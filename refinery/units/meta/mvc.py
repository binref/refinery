#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units import Unit, Chunk
from refinery.lib.meta import metavars


class mvc(Unit):
    """
    Clean up meta variables in the current scope.
    """
    def __init__(self):
        super().__init__(age=age)

    def process(self, data: Chunk):
        meta = metavars(data)
        scope = data.scope
        for key in list(meta.keys()):
            if meta.get_scope(key, scope) < scope:
                continue
            meta.discard(key)
        return data
