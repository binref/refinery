#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units import Arg, Unit


class ccp(Unit):
    """
    Prepend data to the input.
    """

    def __init__(self, data: Arg(help='Binary string to be prepended to the input.')):
        super().__init__(data=data)

    def process(self, data: bytearray):
        data[:0] = self.args.data
        return data
