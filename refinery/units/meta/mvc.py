#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units import Unit, Chunk
from refinery.lib.meta import metavars


class mvc(Unit):
    """
    Clean up meta variables in the current scope.
    """
    def process(self, data: Chunk):
        meta = metavars(data)
        for key in list(meta.keys()):
            meta.discard(key)
        return data
