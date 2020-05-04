#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import arg, Unit


class ccp(Unit):
    """
    Prepend data to the input.
    """

    def __init__(self, *data: arg(help='Binary strings to be prepended to the input.')):
        super().__init__(data=data)

    def process(self, data):
        return B''.join(self.args.data) + data
