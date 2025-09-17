from __future__ import annotations

from refinery.lib.types import Param
from refinery.lib.vfs import VirtualFileSystem
from refinery.units import Arg, Unit


class evtx(Unit):
    """
    Extracts data from Windows Event Log files (EVTX). Each extracted log entry is returned as a single
    output chunk in XML format.
    """

    def __init__(self, raw: Param[bool, Arg.Switch('-r', help='Extract raw event data rather than XML.')] = False):
        super().__init__(raw=raw)

    @Unit.Requires('python-evtx', ['formats'])
    def _evtx():
        from Evtx.Evtx import Evtx
        return Evtx

    def process(self, data):
        with VirtualFileSystem() as vfs:
            raw = self.args.raw
            with self._evtx(vfs.new(data)) as log:
                for record in log.records():
                    yield record.data() if raw else record.xml().encode(self.codec)
