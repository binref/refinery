#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Iterable
from refinery.lib.frame import Chunk

from refinery.units import arg, Unit
from refinery.lib.loader import load_pipeline


class reduce(Unit):
    """
    The reduce unit applies an arbitrary pipeline repeatedly to reduce the current frame to a single chunk.
    """

    def __init__(self,
        *reduction: arg(type=str, metavar='pipeline', help=(
            'The remaining command line is a refinery pipeline. The input for this pipeline is the currently accumulated data '
            'and the next chunk to be combined is passed in a temporary meta variable.'
        )),
        init: arg.binary('-i', help='Optionally specify the initial buffer. When omitted, the first chunk is used.') = None,
        temp: arg('-t', type=str, metavar='name', help='The name of the temporary variable. The default is "{default}".') = 't',
    ):
        super().__init__(reduction=reduction, temp=temp, init=init)

    def filter(self, chunks):
        it: Iterable[Chunk] = iter(chunks)
        name = self.args.temp
        init = self.args.init
        data = next(it) if init is None else self.labelled(init)
        unit: Unit = load_pipeline('\t'.join(self.args.reduction))
        for chunk in it:
            data.meta.update(chunk.meta)
            data[name] = chunk
            unit.args(data)
            data = unit.act(data)
        yield data
