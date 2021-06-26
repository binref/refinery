#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from itertools import cycle
from .. import arg, Unit
from ...lib.tools import lookahead


class sep(Unit):
    """
    Multiple inputs are joined along a specified separator. If any of the input
    `refinery.lib.frame.Chunk`s is currently out of scope, `refinery.sep` turns
    makes them visible by default. This can be prevented by using the `-s` flag.
    """

    def __init__(
        self, *separators: arg(metavar='separator', help='Separator; the default is a single line break.'),
        scoped: arg.switch('-s', help=(
            'Maintain chunk scope; i.e. do not turn all input chunks visible.')) = False
    ):
        separators = separators or [B'\n']
        super().__init__(separators=separators, scoped=scoped)

    def filter(self, chunks):
        for (last, chunk), index in zip(lookahead(chunks), cycle(range(len(self.args.separators)))):
            chunk.temp = index if not last else None
            yield chunk

    def process(self, chunk):
        index = chunk.temp
        yield chunk
        if index is not None:
            yield self.args.separators[index]
