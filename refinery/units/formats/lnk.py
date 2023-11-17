#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units.formats import Unit
from refinery.units.sinks.ppjson import ppjson
from refinery.lib.structures import MemoryFile
from refinery.lib.json import JSONEncoderEx
from refinery.lib.tools import NoLogging


class lnk(Unit):
    """
    Parse Windows Shortcuts (LNK files) and returns the parsed information in JSON format. This
    unit is a thin wrapper around the LnkParse3 library.
    """

    @Unit.Requires('LnkParse3', 'formats', 'default')
    def _LnkParse3():
        import LnkParse3
        return LnkParse3

    def __init__(self, tabular: Unit.Arg('-t', help='Print information in a table rather than as JSON') = False):
        super().__init__(tabular=tabular)

    def process(self, data):
        with NoLogging(NoLogging.Mode.ALL):
            parsed = self._LnkParse3.lnk_file(MemoryFile(data)).get_json()
        with JSONEncoderEx as encoder:
            pp = ppjson(tabular=self.args.tabular)
            yield from pp._pretty_output(
                parsed, indent=4, cls=encoder, ensure_ascii=False)
