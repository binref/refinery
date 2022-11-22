#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units import Arg, Unit
from refinery.lib.meta import metavars


class mvg(Unit):
    """
    This unit can move meta variables into the scope of the parent frame. If used at the end of a
    frame, the variables will be moved the the scope of the frame that the pipeline will return to.
    Otherwise and if the --top switch is being used, variables will be moved to scope 0, i.e. to
    the topmost frame in the current tree.

    If no variables are explicitly specified, all variables in the current chunk will be rescoped.
    """
    def __init__(
        self,
        *names: Arg(type=str, metavar='name', help='Name of a variable to be removed.'),
        top: Arg.Switch('-t', help='Move the variable(s) to the topmost frame layer.') = False
    ):
        super().__init__(names=names, top=top)

    def process(self, data):
        meta = metavars(data)
        nest = self.args.nesting
        if nest < 0 and not self.args.top:
            spot = max(1, meta.scope + nest)
        else:
            spot = 1
        for name in self.args.names or meta.variable_names():
            try:
                if meta.get_scope(name) > spot:
                    meta.set_scope(name, spot)
            except KeyError:
                self.log_info(F'variable not defined: {name}')
        return data
