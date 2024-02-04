#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Iterable

from itertools import islice

from refinery.units import Arg, Unit, Chunk
from refinery.lib.loader import load_pipeline


class reduce(Unit):
    """
    The reduce unit applies an arbitrary pipeline repeatedly to reduce the current frame to a
    single chunk. The first chunk in the frame serves as initialization, and all metadata is
    inherited from it.
    """

    def __init__(self,
        *reduction: Arg(type=str, metavar='pipeline', help=(
            'The remaining command line is a refinery pipeline. The input for this pipeline '
            'is the currently accumulated data and the next chunk to be combined is passed in '
            'a temporary meta variable.'
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
        for chunk in islice(it, 0, just) if just else it:
            accu[name] = chunk
            unit.args(accu)
            self.log_info('current input:', accu, clip=True)
            accu[:] = unit.act(accu)
        yield accu
        yield from it
