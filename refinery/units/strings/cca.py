#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import arg, Unit


class cca(Unit):
    """
    Append data to the input.
    """

    def __init__(self, *data: arg(help='Binary strings to be appended to the input.')):
        super().__init__(data=data)

    def process(self, data):
        return data + B''.join(self.args.data)
