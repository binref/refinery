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

    Note that it is not possible to promote a variable to a parent frame if that variable does not
    have the same value on all chunks in the current frame - such variables will always be removed
    when the frame closes.
    """
    def __init__(
        self,
        *names: Arg(type=str, metavar='name', help=(
            'Name of a variable to be removed. If no variables are explicitly specified, all '
            'variables in the current chunk will be rescoped.'
        )),
        top: Arg.Switch('-t', help='Move the variable(s) to the topmost frame layer.') = False
    ):
        super().__init__(names=names, top=top)

    def process(self, data):
        meta = metavars(data)
        nest = self.args.nesting
        if nest < 0 and not self.args.top:
            spot = meta.scope + nest
        else:
            spot = 1
        for name in self.args.names or meta.variable_names():
            try:
                if meta.get_scope(name) <= spot:
                    continue
                meta.set_scope(name, spot)
            except KeyError:
                self.log_info(F'variable not defined: {name}')
        return data
