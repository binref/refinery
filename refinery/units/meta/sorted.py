#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import arg, Unit, RefineryCriticalException


class sorted(Unit):
    """
    Sorts all elements of the input `refinery.lib.frame` lexicographically.
    This unit is a `refinery.nop` on single inputs.
    """

    def __init__(self, length: arg.switch('-l', help='Sort items by length before sorting lexicographically.')):
        super().__init__(length=length)

    def filter(self, chunks):
        sortbuffer = []
        invisibles = {}

        for k, chunk in enumerate(chunks):
            if not chunk.visible:
                r = k - len(invisibles)
                invisibles.setdefault(r, [])
                invisibles[r].append(chunk)
            else:
                sortbuffer.append(chunk)

        if self.args.length:
            sortbuffer.sort(key=lambda t: (len(t), t))
        else:
            sortbuffer.sort()

        if not invisibles:
            yield from sortbuffer
            return

        for r, chunk in enumerate(sortbuffer):
            if r in invisibles:
                yield from invisibles[r]
                del invisibles[r]
            yield chunk

        if invisibles:
            yield from invisibles[r]
            del invisibles[r]

        if invisibles:
            raise RefineryCriticalException(
                'for unknown reasons, invisible chunks were lost during '
                'the sorting process.'
            )
