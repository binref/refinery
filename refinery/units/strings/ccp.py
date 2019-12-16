#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import Unit
from ...lib.argformats import multibin


class ccp(Unit):
    """
    Prepend data to the input.
    """

    def interface(self, argp):
        argp.add_argument('data', nargs='*', type=multibin, help='specify data to be prepended')
        return super().interface(argp)

    def process(self, data):
        return B''.join(self.args.data) + data
