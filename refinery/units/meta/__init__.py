#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A package for units that operate primarily on frames of several of inputs.
"""
from __future__ import annotations

from typing import Iterable, TYPE_CHECKING
from abc import abstractmethod
if TYPE_CHECKING:
    from ...lib.frame import Chunk

from .. import arg, Unit
from ...lib.argformats import sliceobj


class FrameSlicer(Unit, abstract=True):

    def __init__(self, *slice: arg(
        type=sliceobj, nargs='*', default=[slice(None, None)],
        help='Specify start:stop:step in Python slice syntax.'
    ), **keywords):
        super().__init__(slice=list(slice), **keywords)
        for s in self.args.slice:
            if s.step and s.step < 0:
                raise ValueError('negative slice steps are not supported here')


class ConditionalUnit(Unit, abstract=True):

    def __init__(
        self,
        negate: arg.switch('-n', help='invert the logic of this filter; drop all matching chunks instead of keeping them') = False,
        temporary: arg.switch('-t', help='do not remove chunks from the frame entirely; move them out of scope instead') = False,
        **kwargs
    ):
        super().__init__(negate=negate, temporary=temporary, **kwargs)

    @abstractmethod
    def match(self, chunk) -> bool:
        ...

    def filter(self, chunks: Iterable[Chunk]):
        temporary = self.args.temporary
        for chunk in chunks:
            if not chunk.visible:
                continue
            if self.match(chunk) is self.args.negate:
                if not temporary:
                    continue
                chunk.visible = False
            yield chunk
