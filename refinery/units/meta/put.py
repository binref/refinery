#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import arg, Unit
from ...lib.argformats import numseq
from ...lib.tools import isbuffer


class put(Unit):
    """
    Can be used to add a meta variable to the processed chunk. Note that meta variables
    cease to exist outside a frame.
    """
    def __init__(
        self,
        name : arg(help='The name of the variable to be used.', type=str),
        value: arg(help='The value for the variable.', type=numseq)
    ):
        super().__init__(name=name, value=value)

    def process(self, data):
        value = self.args.value
        if not isbuffer(value):
            if isinstance(value, (list, tuple, set)):
                if len(value) == 1:
                    value = next(iter(value))
            elif not isinstance(value, int):
                raise NotImplementedError('metadata can currently not handle unbounded integer iterables.')
        self.log_debug(F'storing {type(value).__name__}:', value)
        return self.labelled(data, **{self.args.name: value})
