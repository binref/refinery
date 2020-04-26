#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A package for units that operate primarily on frames of several of inputs.
"""
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
