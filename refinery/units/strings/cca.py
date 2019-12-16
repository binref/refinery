#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import Unit
from ...lib.argformats import multibin


class cca(Unit):
    """
    Append data to the input.
    """

    def interface(self, argp):
        argp.add_argument('data', nargs='*', type=multibin, help='specify data to be appended')
        return super().interface(argp)

    def process(self, data):
        return data + B''.join(self.args.data)
