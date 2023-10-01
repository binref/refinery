#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units import Arg, Unit


class ngrams(Unit):
    """
    Extract all n-grams from the input. The algorithm is naive, i.e. it simply iterates all n-grams
    and deduplicates using a set data structure.
    """
    def __init__(
        self, size: Arg.Number(help='Specifies the size of each n-gram, i.e. the number n. Defaults to {default}.') = 2,
    ):
        super().__init__(size=size)

    def process(self, data: bytearray):
        deduplicator = set()
        block_size = self.args.size
        view = memoryview(data)
        for index in range(len(data) - block_size):
            block = bytes(view[index:index + block_size])
            if block in deduplicator:
                continue
            deduplicator.add(block)
            yield block
