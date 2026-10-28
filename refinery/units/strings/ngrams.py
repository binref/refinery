from __future__ import annotations

from refinery.lib.types import Param, bounds
from refinery.units import Arg, Unit


class ngrams(Unit):
    """
    Extract all n-grams from the input.

    The algorithm is naive, i.e. it simply iterates all n-grams and deduplicates using a set
    data structure. The number n is taken from an arbitrary inclusive range given as a Python
    slice expression.
    """
    def __init__(
        self, size: Param[int | slice, Arg.Bounds(intok=True, help=(
            'Specifies the sizes of each n-gram, i.e. the number n. Defaults to {default}.'
        ))] = slice(2, None),
    ):
        super().__init__(size=size)

    def process(self, data: bytearray):
        for n in bounds[self.args.size]:
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
                yield self.carved(block, index, index + n)
