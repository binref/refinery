#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import Unit


class dedup(Unit):
    """
    Deduplicates a sequence of multiple inputs. The deduplication is limited to the current `refinery.lib.frame`.
    """

    def filter(self, chunks):
        barrier = set()
        for chunk in chunks:
            if not chunk.visible:
                yield chunk
                continue
            hashed = hash(chunk)
            if hashed not in barrier:
                barrier.add(hashed)
                yield chunk
