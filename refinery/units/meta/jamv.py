from __future__ import annotations

from refinery.lib.types import Param, buf
from refinery.units import Arg, Chunk, Unit


class jamv(Unit):
    """
    Short for "Join as Meta Variables": It joins all chunks in the current frame into a single one
    by storing the contents of each chunk as the contents of a meta variable in the output.
    """
    def __init__(
        self,
        name: Param[str, Arg.String(metavar='format', help=(
            'A format string that specifies the variable name for storing the chunk.'))],
        data: Param[buf, Arg.Binary(metavar='data', help=(
            'Optionally specify the body of the fused output chunk; empty by default.'))] = None,
    ):
        super().__init__(name=name, data=data)

    def process(self, data: Chunk):
        try:
            meta = data.temp
        except Exception:
            meta = None
        if not isinstance(meta, dict):
            raise RuntimeError('this unit can only be used inside a frame')
        data.meta.update(meta)
        data[:] = self.args.data or B''
        return data

    def filter(self, inputs):
        head = None
        spec = self.args.name
        meta = {}
        for chunk in inputs:
            if not chunk.visible:
                yield chunk
                continue
            used = set()
            name = chunk.meta.format_str(spec, self.codec, [chunk], used=used)
            if head is None:
                for u in used:
                    chunk.meta.discard(u)
                head = chunk
            if name in meta:
                self.log_warn('overwriting duplicate variable:', name, clip=True)
            meta[name] = chunk
        if head:
            head.temp = meta
            yield head
