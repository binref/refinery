#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import arg, Unit, RefineryCriticalException

from ...lib.argformats import PythonExpression
from ...lib.meta import metavars


class sorted(Unit):
    """
    Sorts all elements of the input `refinery.lib.frame` lexicographically.
    This unit is a `refinery.nop` on single inputs.
    """

    def __init__(
        self,
        key: arg('key', type=str, help='A meta variable expression to sort by instead of sorting the content.') = None,
        descending: arg.switch('-d', help='Sort in descending order, the default is ascending.') = False
    ):
        super().__init__(key=key, descending=descending)

    def filter(self, chunks):
        sortbuffer = []
        invisibles = {}
        key = self.args.key

        if key is not None:
            def _key(chunk):
                return expression(metavars(chunk)), chunk
            expression = PythonExpression(key, all_variables_allowed=True)
            key = _key

        for k, chunk in enumerate(chunks):
            if not chunk.visible:
                r = k - len(invisibles)
                invisibles.setdefault(r, [])
                invisibles[r].append(chunk)
            else:
                sortbuffer.append(chunk)

        sortbuffer.sort(key=key, reverse=self.args.descending)

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
