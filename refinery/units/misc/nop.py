#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units import Unit
from refinery.lib.argparser import ArgumentParserWithKeywordHooks
from refinery.lib.tools import documentation


class NopArgParser(ArgumentParserWithKeywordHooks):
    def parse_args(self, args, namespace=None):
        parsed, _ = self.parse_known_args(args, namespace=namespace)
        return parsed


class nop(Unit):
    """
    The unit generates the exact output that was received as input. All unknown arguments passed
    to nop are completely ignored, which is different from the behavior of other units. As such,
    nop can be used to comment out other units in longer refinery pipelines by simply prefixing a
    command with nop.
    """
    @classmethod
    def argparser(cls, **keywords):
        argp = NopArgParser(
            keywords, prog=cls.name, description=documentation(cls), add_help=False)
        argp.set_defaults(nesting=0)
        return cls._interface(argp)
