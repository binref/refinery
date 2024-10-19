#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import pathlib

from refinery.units import Unit
from refinery.lib.structures import MemoryFile
from refinery.lib.meta import metavars


class uuenc(Unit):
    """
    Unit for uuencode.
    """
    @property
    def _uu(self):
        import uu
        return uu

    def process(self, data):
        with MemoryFile(data) as stream:
            with MemoryFile() as output:
                self._uu.decode(stream, output, quiet=True)
                return output.getvalue()

    def reverse(self, data):
        meta = metavars(data)
        path = meta.get('path', None)
        name = path and pathlib.Path(path).name
        with MemoryFile(data) as stream:
            with MemoryFile() as output:
                self._uu.encode(stream, output, name, backtick=True)
                return output.getvalue()
