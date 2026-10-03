from __future__ import annotations

from refinery.lib.types import Param
from refinery.units import Arg, Chunk, Unit


class group(Unit):
    """
    Group incoming chunks into frames of the given size.
    """
    def __init__(self, size: Param[int, Arg.Number(help='The size of each group.', bound=(1, None))]):
        super().__init__(size=size)

    def process(self, data: Chunk):
        if not data.temp:
            return
        yield from data.temp

    def filter(self, chunks):
        size = self.args.size
        members: list[Chunk] = []
        for chunk in chunks:
            if not chunk.visible:
                yield chunk
                continue
            members.append(chunk)
            if len(members) < size:
                continue
            head = members[0]
            head.temp = members
            members = []
            yield head
        if members:
            head = members[0]
            head.temp = members
            yield head
