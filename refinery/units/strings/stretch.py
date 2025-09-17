from __future__ import annotations

from itertools import cycle, islice, repeat

from refinery.lib.types import Param
from refinery.units import Arg, Unit


class stretch(Unit):
    """
    Stretch the input data by repeating every byte a number of times.
    """
    def __init__(self, *count: Param[int, Arg.Number(metavar='count', help=(
        'The number of times every byte should be repeated. By default,  '
        'every byte is repeated once.'
    ))]):
        count = count or (2,)
        if any(k <= 0 for k in count):
            raise ValueError('You can not use a stretching factor of less than 1.')
        super().__init__(count=count or (2,))

    def process(self, data):
        def stretched(it):
            factor = cycle(self.args.count)
            for byte in it:
                yield from repeat(byte, next(factor))
        return bytearray(stretched(iter(data)))

    def reverse(self, data):
        # one-sided inverse
        def clinched(it):
            factor = cycle(self.args.count)
            while True:
                try:
                    take = islice(it, next(factor))
                    yield next(take)
                    for _ in take: pass
                except StopIteration:
                    break
        return bytearray(clinched(iter(data)))
