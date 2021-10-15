#!/usr/bin/env python3
# -*- coding: utf - 8 -* -
from refinery.units import Unit
from refinery.lib.vfs import VirtualFileSystem, VirtualFile


class evtx(Unit):
    """
    Extracts data from Windows Event Log files (EVTX). Each extracted log entry is returned as a single
    output chunk in XML format.
    """

    def __init__(self, raw: Unit.Arg.switch('-r', help='Extract raw event data rather than XML.') = False):
        super().__init__(raw=raw)

    @Unit.Requires('python-evtx')
    def _evtx():
        from Evtx.Evtx import Evtx
        return Evtx

    def process(self, data):
        with VirtualFileSystem() as vfs:
            raw = self.args.raw
            with self._evtx(VirtualFile(vfs, data)) as log:
                for record in log.records():
                    yield record.data() if raw else record.xml().encode(self.codec)
