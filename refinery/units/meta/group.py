from __future__ import annotations

from itertools import islice

from refinery.lib.types import Param
from refinery.units import Arg, Chunk, Unit


class group(Unit):
    """
    Group incoming chunks into frames of the given size.
    """
    def __init__(self, size: Param[int, Arg.Number(help='Size of each group; must be at least 2.', bound=(2, None))]):
        super().__init__(size=size)

    def process(self, data: Chunk):
        if not data.temp:
            return
        yield data
        yield from islice(data.temp, 0, self.args.size - 1)

    def filter(self, chunks):
        it = iter(chunks)
        while True:
            try:
                head: Chunk = next(it)
            except StopIteration:
                return
            head.temp = it
            yield head
