#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units.formats import PathExtractorUnit, UnpackResult
from refinery.lib.meta import metavars


class xtvba(PathExtractorUnit):
    """
    Extract VBA macro code from Office documents.
    """
    @PathExtractorUnit.Requires('oletools')
    def _olevba():
        from oletools import olevba
        return olevba

    def unpack(self, data):
        parser = self._olevba.VBA_Parser(
            metavars(data).get('path', None), data=bytes(data), relaxed=True)
        for _, path, _, code in parser.extract_all_macros():
            yield UnpackResult(path, code.encode(self.codec))
