#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from itertools import cycle
from .. import arg, Unit


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
        it = iter(chunks)
        try:
            chunk = next(it)
        except StopIteration:
            return
        separator = cycle([self.labelled(s) for s in self.args.separators])
        yield chunk
        for chunk in it:
            yield next(separator)
            yield chunk
