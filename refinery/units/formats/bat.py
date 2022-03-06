#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from refinery.units import Unit
from refinery.lib.thirdparty.batch_interpreter import STRIP, BatchDeobfuscator
from refinery.lib.decorators import unicoded


class bat(Unit):
    """
    Deobfuscates batch files, based on the batch deobfuscator by DissectMalware. The input script
    is interpreted, variables are substituted for previously defined values, including commonly
    defined operating system environment variables. Variable definitions that are later evaluated
    are removed from the script, as are all echo commands and comments.
    """
    def __init__(
        self,
        keep_all         : Unit.Arg.switch('-a', help='Do not strip anything after deobfuscation.'),
        keep_comment     : Unit.Arg.switch('-c', help='Do not strip comments from the script.'),
        keep_definitions : Unit.Arg.switch('-d', help='Do not strip variable definitions.'),
        keep_echo        : Unit.Arg.switch('-e', help='Do not strip echo calls in the script.'),
    ): ...

    @unicoded
    def process(self, data: str) -> str:
        mode = STRIP.ALL
        if self.args.keep_all:
            mode = STRIP.NONE
        elif self.args.keep_comment:
            mode ^= STRIP.COMMENT
        elif self.args.keep_definitions:
            mode ^= STRIP.DEFINITION
        elif self.args.keep_echo:
            mode ^= STRIP.ECHO
        return BatchDeobfuscator().deobfuscate(data, mode)
