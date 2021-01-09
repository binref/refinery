#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A package for units that operate primarily on frames of several of inputs.
"""
from .. import arg, Unit
from ...lib.argformats import sliceobj


def check_variable_name(name: str) -> str:
    """
    All single-letter, uppercase variable names are reserved.
    """
    if len(name) == 1 and ord(name[0]) in range(65, 90 + 1):
        raise ValueError('Single uppercase letter variable names are reserved.')
    if not name.isprintable():
        raise ValueError('Variable names must consist of printable characters.')
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
