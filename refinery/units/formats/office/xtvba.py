#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from uuid import uuid4

from refinery.lib.tools import NoLogging
from refinery.units.formats import PathExtractorUnit, UnpackResult


class xtvba(PathExtractorUnit):
    """
    Extract VBA macro code from Office documents.
    """
    @PathExtractorUnit.Requires('oletools', 'formats', 'office', 'extended')
    def _olevba():
        with NoLogging(NoLogging.Mode.ALL):
            import oletools.olevba
            return oletools.olevba

    def unpack(self, data):
        sentinel = uuid4()
        try:
            parser = self._olevba.VBA_Parser(sentinel, data=bytes(data), relaxed=True)
        except self._olevba.FileOpenError:
            raise ValueError('Input data not recognized by VBA parser')
        for p1, stream_path, p2, code in parser.extract_all_macros():
            if not stream_path:
                if p1 == sentinel:
                    continue
                if p2 == sentinel:
                    continue
            yield UnpackResult(stream_path, code.encode(self.codec))
