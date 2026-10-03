from __future__ import annotations

from typing import Iterable

from refinery.lib.argformats import DelayedBinaryArgument
from refinery.lib.types import Param
from refinery.units import Arg, Chunk, Unit


class reduce(Unit):
    """
    Apply an arbitrary multibin suffix repeatedly to reduce a complete frame to a single
    chunk.

    The reduce unit applies an arbitrary multibin suffix repeatedly to reduce a complete
    frame to a single chunk. The first chunk in the frame serves as initialization.
    """

    def __init__(self,
        suffix: Param[str, Arg.String(help=(
            'The remaining command line is a multibin suffix. The reduction accumulator is initialized '
            'with the first chunk in the frame. Then, each remaining chunk is processed with the given '
            'suffix and the result is used to overwrite the accumulator.'
        ))],
        just: Param[int, Arg.Number('-j',
            help='Optionally specify a maximum number of chunks to process beyond the first.')] = 0,
        temp: Param[str, Arg.String('-t', metavar='name',
            help='The name of the accumulator variable. The default is "{default}".')] = 't',
    ):
        super().__init__(suffix=suffix, temp=temp, just=just)

    def filter(self, chunks: Iterable[Chunk]):
        it = iter(chunks)
        just = self.args.just
        name = self.args.temp
        for accu in it:
            if accu.visible:
                break
            yield accu
        else:
            return
        if just:
            self.log_info(F'reducing only the next {just} chunks')
        reduced = 0
        for chunk in it:
            if not chunk.visible:
                yield chunk
                continue
            chunk.meta[name] = accu
            accu[:] = DelayedBinaryArgument(self.args.suffix, reverse=True, seed=chunk)(chunk)
            self.log_debug('reduced:', accu, clip=True)
            reduced += 1
            if reduced == just:
                break
        accu.meta.discard(name)
        yield accu
        yield from it
