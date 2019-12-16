#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import Unit


class dedup(Unit):
    """
    Deduplicates a sequence of multiple inputs, and optionally sorts them.
    """

    def interface(self, argp):
        argp.add_argument(
            '-s', '--sort',
            action='store_true',
            help='Sort results.'
        )
        return super().interface(argp)

    def filter(self, inputs):
        def deduplicate():
            barrier = set()
            for item in inputs:
                hashed = hash(item)
                if hashed not in barrier:
                    barrier.add(hashed)
                    yield item
        if self.args.sort:
            yield from sorted(deduplicate())
        else:
            yield from deduplicate()
