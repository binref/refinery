#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import uu
import pathlib

from refinery.units import Unit
from refinery.lib.structures import MemoryFile
from refinery.lib.meta import metavars


class uuenc(Unit):
    """
    Unit for uuencode.
    """
    def process(self, data):
        with MemoryFile(data) as stream:
            with MemoryFile() as output:
                uu.decode(stream, output, quiet=True)
                return output.getvalue()

    def reverse(self, data):
        meta = metavars(data)
        path = meta.get('path', None)
        name = path and pathlib.Path(path).name
        with MemoryFile(data) as stream:
            with MemoryFile() as output:
                uu.encode(stream, output, name, backtick=True)
                return output.getvalue()
