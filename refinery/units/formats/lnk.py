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

    @Unit.Requires('LnkParse3>=1.4.0', 'formats', 'default', 'extended')
    def _LnkParse3():
        import LnkParse3
        return LnkParse3

    _PATHS = {
        'data': ...,
        'header': {'creation_time', 'accessed_time', 'modified_time', 'windowstyle'},
        'link_info': {'local_base_path', 'location'},
    }

    def __init__(
        self,
        tabular: Unit.Arg('-t', help='Print information in a table rather than as JSON.') = False,
        details: Unit.Arg('-d', help='Print all details; some properties are hidden by default.') = False,
    ):
        super().__init__(tabular=tabular, details=details)

    def process(self, data):
        with NoLogging():
            parsed = self._LnkParse3.lnk_file(MemoryFile(data)).get_json()
        if not self.args.details:
            paths = self._PATHS
            noise = [key for key in parsed if key not in paths]
            for key in noise:
                del parsed[key]
            for path, scope in paths.items():
                if scope is (...):
                    continue
                try:
                    section = parsed[path]
                except KeyError:
                    continue
                noise = [key for key in section if key not in scope]
                for key in noise:
                    del section[key]
        with JSONEncoderEx as encoder:
            pp = ppjson(tabular=self.args.tabular)
            yield from pp._pretty_output(
                parsed, indent=4, cls=encoder, ensure_ascii=False)
