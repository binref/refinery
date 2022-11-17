#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units import Arg, Unit
from refinery.lib.meta import metavars


class mvg(Unit):
    """
    The unit can turn frame-local meta variables into global ones. The modified variables will remain
    available in any parent frame of the current one. If no variables are explicitly specified, the unit
    makes all variables in the current chunk global.
    """
    def __init__(self, *name: Arg(help='The name of the variable to be moved out of scope.', type=str)):
        super().__init__(names=name)

    def process(self, data):
        meta = metavars(data)
        for name in self.args.names or meta.keys():
            try:
                meta.set_scope(name, 0)
            except KeyError:
                self.log_info(F'variable not defined: {name}')
        return data
