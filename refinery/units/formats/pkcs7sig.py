#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units import Unit, Arg
from refinery.units.formats.pe.pemeta import pemeta
from refinery.units.sinks.ppjson import ppjson


class pkcs7sig(Unit):
    """
    Converts PKCS7 encoded signatures into a human-readable JSON representation. This can be used
    to parse authenticode signatures appended to files that are not PE files to get the same output
    that is produced by the pemeta unit.
    """
    def __init__(self, tabular: Arg('-t', help='Print information in a table rather than as JSON') = False):
        super().__init__(tabular=tabular)

    def process(self, data: bytes):
        json = pemeta.parse_signature(data)
        yield from ppjson(tabular=self.args.tabular)._pretty_output(json, indent=4, ensure_ascii=False)
