#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import defusedxml.minidom

from .. import arg, Unit
from ...lib.decorators import unicoded


class ppxml(Unit):
    """
    Expects XML input data and outputs it in a neatly formatted manner.
    """

    def __init__(self, indent: arg.number('-i', help=(
        'Controls the amount of space characters used for indentation in the output. Default is 4.')) = 4
    ):
        super().__init__(indent=indent)

    @unicoded
    def process(self, data: str) -> str:
        node = defusedxml.minidom.parseString(data)
        if '<?xml' not in data:
            node = node.childNodes[0]
        return '\n'.join(s for s in node.toprettyxml(
            self.args.indent * ' ').splitlines() if s and not s.isspace())
