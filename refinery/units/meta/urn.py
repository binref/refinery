from __future__ import annotations

from itertools import combinations, combinations_with_replacement, permutations, product
from typing import Iterable

from refinery.lib.argformats import sliceobj
from refinery.lib.types import Param
from refinery.units import Arg, Chunk, Unit


class urn(Unit):
    """
    Treat the chunks in the current frame as items in an urn and produce every possible sequence
    that could occur as a sequence of draws. For example, selecting both -k and -s is equivalent
    to generating all possible permutations of these chunks.
    """

    def __init__(self,
        size: Param[str, Arg.String(metavar='a:b', help=(
            'Generate sequences of length x, where x is in [a:b]. The default value is {default}, '
            'where N is the number of chunks in the current frame.'))] = 'N:N',
        keep: Param[bool, Arg.Switch('-k', help=(
            'Chunks are not returned back to the urn after being drawn.'))] = False,
        sort: Param[bool, Arg.Switch('-s', help=(
            'The order of items does not matter; for the output, chunks are sorted according to '
            'their original position in the frame.'))] = False
    ):
        super().__init__(size=size, keep=keep, sort=sort)

    def process(self, data: Chunk):
        yield from data.temp

    def filter(self, chunks: Iterable[Chunk]):
        it = iter(chunks)
        head = next(it)
        buffer = [bytes(head)]
        buffer.extend(bytes(c) for c in it)
        head = head.copy(meta=True, data=False)
        head.meta['N'] = len(buffer)
        size = sliceobj(self.args.size, head)
        a = size.start or 1
        b = size.stop or len(buffer)
        b = max(b, a + 1)
        c = size.step or 1
        self.log_debug(F'using size [{a}:{b}:{c}]')
        s = 1 if self.args.sort else 0
        k = 1 if self.args.keep else 0
        m = (s << 1) | k
        method = {
            0b00: lambda i, r: product(i, repeat=r),
            0b01: combinations,
            0b10: combinations_with_replacement,
            0b11: permutations
        }[m]
        self.log_info(F'choosing {method.__name__}')
        for n in range(a, b, c):
            self.log_debug(F'generating sequences of length {n}')
            for head.temp in method(buffer, n):
                yield head
