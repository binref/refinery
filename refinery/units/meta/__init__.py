#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A package for units that operate primarily on frames of several of inputs.
"""
from .. import Unit
from ...lib.argformats import sliceobj


class FrameSlicer(Unit, abstract=True):

    @classmethod
    def interface(cls, argp):
        argp.add_argument(
            'slice',
            type=sliceobj,
            nargs='*',
            default=[slice(None, None)],
            help='Specify start:stop:step in Python slice syntax.'
        )
        return super().interface(argp)

    def __init__(self, *args, **kw):
        super().__init__(*args, **kw)
        for s in self.args.slice:
            if s.step and s.step < 0:
                raise ValueError('negative slice steps are not supported here')
