from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from refinery.lib.types import Param
from refinery.units import Arg, Chunk, Unit


class xfcc(Unit):
    """
    The cross frame chunk count unit! It computes the number of times a chunk occurs across several frames
    of input. It consumes all frames at its current level of the frame tree and counts the number of times
    each item occurs in each of them. It converts a frame tree of depth 2 into a new frame tree of depth 2
    where the parent of every leaf has this leaf as its only child. The leaves of this tree have been
    enriched with a meta variable containing the number of times the corresponding chunk has occurred in
    the input frame tree. The variable that stores this information is scoped at the first layer of this
    subtree, which means that a frame can be closed once after invocation of xfcc and the variable remains
    accessible. This unit can be used to compute set intersections across frames as follows:

        (1) [| (2) [| dedup | xfcc -r t ]| iff t==1 | (3) ]

    A sequence of chunks is emitted at (1), each of which has chunks extracted at (2). It is then important
    to use dedup before calling xfcc, since xfcc performs an absolute count. The frame at (3) contains the
    intersection of all datasets that were extracted at (2).
    """
    def __init__(
        self,
        variable: Param[str, Arg(help='The variable which is used as the accumulator')] = 'count',
        relative: Param[bool, Arg.Switch('-r', help='Normalize the accumulator to a number between 0 and 1.')] = False
    ):
        super().__init__(variable=variable, relative=relative)
        self._trunk = None
        self._store: dict[Chunk, int] = defaultdict(int)

    def finish(self):
        vn = self.args.variable
        rc = self.args.relative
        if rc and self._store:
            maximum = max(self._store.values())
        for index, (chunk, count) in enumerate(self._store.items()):
            if rc:
                count /= maximum
            chunk.path[-2] = 0
            chunk.path[-1] = index
            chunk.meta[vn] = count
            chunk.meta.set_scope(vn, chunk.scope - 1)
            yield chunk
        self._store.clear()

    def _getcount(self, chunk):
        try:
            count = int(chunk.meta[self.args.variable])
        except (AttributeError, KeyError, TypeError):
            return 1
        else:
            return count

    def filter(self, chunks: Iterable[Chunk]):
        it = iter(chunks)
        try:
            head = next(it)
        except StopIteration:
            return
        if len(head.path) < 2:
            self.log_warn(F'the current frame is nested {len(head.path)} layers deep, at least two layers are required.')
            yield head
            yield from it
            return
        trunk = head.path[:-2]
        store = self._store
        if trunk != self._trunk:
            yield from self.finish()
            self._trunk = trunk
        store[head] += self._getcount(head)
        for chunk in it:
            store[chunk] += self._getcount(chunk)
