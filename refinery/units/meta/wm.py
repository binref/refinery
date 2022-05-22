#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Iterable

from refinery.units import Unit, Chunk


class wm(Unit):
    """
    The unit wipes all metadata from a chunk; it has no effect outside a chunk.
    It is equivalent to calling `refinery.cm` with only the `-r` switch and is
    provided only as syntactic sugar.
    """
    def filter(self, chunks: Iterable[Chunk]):
        for chunk in chunks:
            chunk.meta.clear()
            yield chunk
