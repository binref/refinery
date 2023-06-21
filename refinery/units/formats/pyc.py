#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from datetime import datetime

from refinery.units import Unit
from refinery.units.formats.archive.xtpyi import decompile_buffer, extract_code_from_buffer
from refinery.lib.meta import metavars


class pyc(Unit):
    """
    Decompiles Python bytecode (PYC) files back to source code. A known limitation is that it does
    not work on recent Python versions, but anything below 3.9 should work.
    """

    def process(self, data):
        for code in extract_code_from_buffer(bytes(data), metavars(data).get('path')):
            meta = {}
            if code.container.co_filename:
                meta.update(path=code.container.co_filename)
                meta.update(date=datetime.fromtimestamp(code.timestamp).isoformat(' ', 'seconds'))
            yield self.labelled(decompile_buffer(code), **meta)
