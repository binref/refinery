#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import arg, Unit


class mput(Unit):
    """
    Can be used to add a meta variable to the processed chunk. Note that meta variables
    cease to exist outside a frame.
    """
    def __init__(
        self,
        name : arg(help='The name of the variable to be used.', type=str),
        value: arg(help='The value for the variable.')
    ):
        super().__init__(name=name, value=value)

    def process(self, data):
        return {'data': data, self.args.name: self.args.value}
