#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Iterable

from itertools import islice

from refinery.units import Arg, Unit, Chunk
from refinery.lib.loader import load_pipeline


class reduce(Unit):
    """
    The reduce unit applies an arbitrary pipeline repeatedly to reduce the current frame to a
    single chunk. The first chunk in the frame serves as initialization.
    """

    def __init__(self,
        *reduction: Arg(type=str, metavar='pipeline', help=(
            'The remaining command line is a refinery pipeline. While reducing the frame, the '
            'binary contents of each chunk are placed in a temporary variable, then the chunk '
            'body is replaced with the accumulated data, and then processed with this pipeline. '
            'The result is written back to the accumulator and the process repeats.'
        )),
        just: Arg.Number('-j',
            help='Optionally specify a maximum number of chunks to process beyond the first.') = 0,
        temp: Arg.String('-t', metavar='name',
            help='The name of the temporary variable. The default is "{default}".') = 't',
    ):
        super().__init__(reduction=reduction, temp=temp, just=just)

    def filter(self, chunks: Iterable[Chunk]):
        it = iter(chunks)
        just = self.args.just
        name = self.args.temp
        accu = next(it)
        init = ' '.join(self.args.reduction)
        unit: Unit = load_pipeline(init)
        meta = dict(accu.meta)
        for chunk in islice(it, 0, just) if just else it:
            accu.meta.update(chunk.meta)
            accu[name] = chunk
            unit.args(accu)
            self.log_info('current input:', accu, clip=True)
            accu[:] = unit.act(accu)
        temp = [key for key in accu.meta.keys() if key not in meta]
        for key in temp:
            accu.meta.discard(key)
        accu.meta.update(meta)
        yield accu
        yield from it
