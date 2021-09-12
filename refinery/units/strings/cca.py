#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import arg, Unit


class cca(Unit):
    """
    Append data to the input.
    """

    def __init__(self, data: arg(help='Binary string to be appended to the input.')):
        super().__init__(data=data)

    def process(self, data: bytearray):
        data.extend(self.args.data)
        return data
