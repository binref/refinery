#!/usr/bin/env python3
# -*- coding: utf - 8 -* -
from refinery.units import RefineryImportMissing, Unit
from refinery.lib.vfs import VirtualFileSystem, VirtualFile


class evtx(Unit):
    """
    Extracts data from Windows Event Log files (EVTX). Each extracted log entry is returned as a single
    output chunk in XML format.
    """

    def __init__(self, raw: Unit.Arg.switch('-r', help='Extract raw event data rather than XML.') = False):
        super().__init__(raw=raw)

    def process(self, data):
        try:
            from Evtx.Evtx import Evtx
        except ImportError:
            raise RefineryImportMissing('python-evtx')
        with VirtualFileSystem() as vfs:
            raw = self.args.raw
            with Evtx(VirtualFile(vfs, data)) as log:
                for record in log.records():
                    yield record.data() if raw else record.xml().encode(self.codec)
