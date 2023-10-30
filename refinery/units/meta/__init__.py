#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A package for units that operate primarily on frames of several of inputs.
"""
from __future__ import annotations

from typing import Iterable, TYPE_CHECKING
from abc import abstractmethod
if TYPE_CHECKING:
    from refinery.lib.frame import Chunk

from refinery.units import Arg, Unit


class FrameSlicer(Unit, abstract=True):

    def __init__(self, *slice: Arg.Bounds(nargs='*', default=[slice(None, None)]), **keywords):
        super().__init__(slice=list(slice), **keywords)
        for s in self.args.slice:
            if s.step and s.step < 0:
                raise ValueError('negative slice steps are not supported here')


class ConditionalUnit(Unit, abstract=True):
    """
    Conditional units can be used in two different ways. When a new frame opens after using this
    unit, chunks that did not match the condition are moved out of scope for that frame but still
    exist and will re-appear after the frame closes. When used inside a frame, however, the unit
    works as a filter and will discard any chunks that do not match.
    """

    def __init__(
        self,
        negate: Arg.Switch('-n', help='invert the logic of this filter; drop all matching chunks instead of keeping them') = False,
        single: Arg.Switch('-s', help='discard all chunks after filtering a single one that matches the condition') = False,
        **kwargs
    ):
        super().__init__(negate=negate, single=single, **kwargs)

    @abstractmethod
    def match(self, chunk) -> bool:
        ...

    def filter(self, chunks: Iterable[Chunk]):
        single: bool = self.args.single
        negate: bool = self.args.negate
        nested: bool = self.args.nesting > 0 or self.args.squeeze
        for chunk in chunks:
            skipped = chunk.visible and self.match(chunk) is negate
            if skipped:
                if not nested:
                    continue
                chunk.set_next_scope(False)
            yield chunk
            if single and not skipped:
                break
