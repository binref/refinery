from __future__ import annotations

from http.client import HTTPResponse, IncompleteRead

from refinery.lib.structures import MemoryFile
from refinery.units import RefineryPartialResult, Unit
from refinery.units.misc.datefix import datefix


class SockWrapper(MemoryFile):
    def sendall(self, ___):
        pass

    def makefile(self, *_):
        return self


class httpresponse(Unit):
    """
    Parses HTTP response text, as you would obtain from a packet dump. This can be
    useful if chunked or compressed transfer encoding was used.
    """
    def process(self, data):
        with SockWrapper(data) as mock:
            mock.seek(0)
            parser = HTTPResponse(mock) # type:ignore
            parser.begin()
            try:
                payload = parser.read()
            except IncompleteRead as incomplete:
                msg = F'incomplete read: {len(incomplete.partial)} bytes processed, {incomplete.expected} more expected'
                raise RefineryPartialResult(msg, incomplete.partial) from incomplete
            try:
                date = parser.headers['date'] | datefix | str
            except Exception:
                pass
            else:
                if len(date) == 19:
                    payload = self.labelled(payload, date=date)
            return payload

    @classmethod
    def handles(cls, data) -> bool | None:
        return data[:6] == B'HTTP/1'
