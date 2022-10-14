#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from hashlib import md5
from refinery.units import Unit


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
            hashed = md5(chunk).digest()
            if hashed not in barrier:
                barrier.add(hashed)
                yield chunk
