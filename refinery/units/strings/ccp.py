#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units import Arg, Unit


class ccp(Unit):
    """
    Short for ConCatPrepend: This unit concatenates the input data with its argument by
    prepending the latter to the former. See also `refinery.cca` for the unit that appends
    instead.
    """

    def __init__(self, data: Arg(help='Binary string to be prepended to the input.')):
        super().__init__(data=data)

    def process(self, data: bytearray):
        data[:0] = self.args.data
        return data
