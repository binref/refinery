#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import defusedxml.minidom

from .. import Unit
from ...lib.decorators import unicoded
from ...lib.argformats import number


class ppxml(Unit):
    """
    Expects XML input data and outputs it in a neatly formatted manner.
    """
    def interface(self, argp):
        argp.add_argument('-i', '--indent', type=number, default=4,
            help='Controls the amount of space characters used for indentation in the output. Default is 4.')
        return super().interface(argp)

    @unicoded
    def process(self, data: str) -> str:
        return defusedxml.minidom.parseString(data).toprettyxml(self.args.indent * ' ').strip()
