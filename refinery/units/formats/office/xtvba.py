#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units.formats import PathExtractorUnit, UnpackResult
from refinery.lib.meta import metavars


class xtvba(PathExtractorUnit):
    """
    Extract VBA macro code from Office documents.
    """

    def unpack(self, data):
        from oletools import olevba
        parser = olevba.VBA_Parser(
            metavars(data).get('path', None), data=bytes(data), relaxed=True)
        for _, path, _, code in parser.extract_all_macros():
            yield UnpackResult(path, code.encode(self.codec))
