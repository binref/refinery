#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import arg, Unit

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
        ascending: arg.switch('-a', help='Sort in ascending order, the default is descending.') = False
    ):
        super().__init__(key=key, ascending=ascending)

    def filter(self, chunks):
        sortbuffer = []
        invisibles = []
        key = self.args.key
        rev = not self.args.ascending

        if key is not None:
            def _key(chunk):
                return expression(metavars(chunk)), chunk
            expression = PythonExpression(key, all_variables_allowed=True)
            key = _key

        def sorted():
            if not sortbuffer:
                return
            sortbuffer.sort(key=key, reverse=rev)
            yield from sortbuffer
            sortbuffer.clear()

        for chunk in chunks:
            if chunk.visible:
                yield from invisibles
                invisibles.clear()
                sortbuffer.append(chunk)
            else:
                yield from sorted()
                invisibles.append(chunk)

        yield from invisibles
        yield from sorted()
