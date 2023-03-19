#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units import Unit, Arg


class dedup(Unit):
    """
    Deduplicates a sequence of multiple inputs. The deduplication is limited to the current `refinery.lib.frame`.
    """
    def __init__(self, count: Arg.Switch('-c', help='Store the count of each deduplicated chunk.') = False):
        super().__init__(count=count)

    def filter(self, chunks):
        if self.args.count:
            from collections import Counter
            barrier = Counter(chunks)
            for chunk in chunks:
                if not chunk.visible:
                    yield chunk
                    continue
                barrier.update(chunk)
            for chunk, count in barrier.items():
                chunk.meta['count'] = count
                yield chunk
        else:
            from hashlib import md5
            barrier = set()
            for chunk in chunks:
                if not chunk.visible:
                    yield chunk
                    continue
                hashed = md5(chunk).digest()
                if hashed not in barrier:
                    barrier.add(hashed)
                    yield chunk
