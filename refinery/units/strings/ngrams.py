from __future__ import annotations

from refinery.lib.tools import integers_of_slice
from refinery.lib.types import Param
from refinery.units import Arg, Unit


class ngrams(Unit):
    """
    Extract all n-grams from the input. The algorithm is naive, i.e. it simply iterates all n-grams
    and deduplicates using a set data structure. The number n is taken from an arbitrary range given
    as a Python slice expression.
    """
    def __init__(
        self, size: Param[slice, Arg.Bounds(
            help='Specifies the sizes of each n-gram, i.e. the number n. Defaults to {default}.')] = slice(2, None),
    ):
        super().__init__(size=size)

    def process(self, data: bytearray):
        for n in integers_of_slice(self.args.size):
            self.log_info(F'emitting {n}-grams')
            if n > len(data):
                break
            deduplicator = set()
            view = memoryview(data)
            for index in range(len(data) - n + 1):
                block = bytes(view[index:index + n])
                if block in deduplicator:
                    continue
                deduplicator.add(block)
                yield self.labelled(block, offset=index)
