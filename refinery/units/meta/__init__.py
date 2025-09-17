"""
A package for units that operate primarily on frames of several of inputs.
"""
from __future__ import annotations

import abc

from refinery.lib.types import Param
from refinery.units import Arg, Chunk, Unit


class FrameSlicer(Unit, abstract=True):

    def __init__(self, *slice: Param[slice, Arg.Bounds(nargs='*', default=[slice(None, None)])], **keywords):
        super().__init__(slice=list(slice), **keywords)
        for s in self.args.slice:
            if s.step and s.step < 0:
                raise ValueError('negative slice steps are not supported here')


class ConditionalUnit(Unit, abstract=True):
    """
    Note: The reverse operation of a conditional unit uses the logical negation of its condition.
    """

    def __init__(
        self,
        retain: Param[bool, Arg.Switch('-r',
            help='Move non-matching chunks out of scope rather than discarding them.')] = False,
        **kwargs
    ):
        super().__init__(retain=retain, **kwargs)

    @abc.abstractmethod
    def match(self, chunk) -> bool:
        ...

    def process(self, chunk: Chunk):
        if not self.match(chunk):
            if not self.args.retain:
                return
            chunk.visible = False
        yield chunk

    def reverse(self, chunk: Chunk):
        if self.match(chunk):
            if not self.args.retain:
                return
            chunk.visible = False
        yield chunk
