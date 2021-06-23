#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A package for units that operate primarily on frames of several of inputs.
"""
import abc

from .. import arg, Unit
from ...lib.argformats import sliceobj


def check_variable_name(name: str) -> str:
    """
    All single-letter, uppercase variable names are reserved.
    """
    if len(name) == 1 and name.upper() == name:
        raise ValueError('Single uppercase letter variable names are reserved.')
    if not name.isidentifier():
        raise ValueError('Variable names must be identifiers.')
    return name


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
        **kwargs
    ):
        super().__init__(negate=negate, **kwargs)

    @abc.abstractmethod
    def match(self, chunk) -> bool:
        ...

    def filter(self, chunks):
        for chunk in chunks:
            if self.match(chunk) is self.args.negate:
                continue
            yield chunk
