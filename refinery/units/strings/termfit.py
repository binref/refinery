#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units import Arg, Unit
from refinery.lib.tools import terminalfit
from refinery.lib.decorators import unicoded


class termfit(Unit):
    """
    Reformat incoming text data to fit a certain width.
    """

    def __init__(
        self,
        width: Arg('width', help='Optionally specify the width, by default the current terminal width is used.') = 0,
        delta: Arg.Number('-d', help='Subtract this number from the calculated width (0 by default).') = 0,
        tight: Arg.Switch('-t', help='Separate paragraphs by a single line break instead of two.') = False,
    ):
        super().__init__(width=width, delta=delta, tight=tight)

    @unicoded
    def process(self, data: str) -> str:
        parsep = '\n' if self.args.tight else '\n\n'
        return terminalfit(data, self.args.delta, self.args.width, parsep)
