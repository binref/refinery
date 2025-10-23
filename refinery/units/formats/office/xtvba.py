from __future__ import annotations

from uuid import uuid4

from refinery.lib.id import buffer_contains
from refinery.lib.tools import NoLogging
from refinery.units.formats import PathExtractorUnit, UnpackResult


class xtvba(PathExtractorUnit):
    """
    Extract VBA macro code from Office documents.
    """
    @PathExtractorUnit.Requires('oletools', ['formats', 'office', 'extended'])
    def _olevba():
        with NoLogging(NoLogging.Mode.ALL):
            import oletools.olevba
            return oletools.olevba

    def unpack(self, data):
        sentinel = str(uuid4())
        try:
            parser = self._olevba.VBA_Parser(sentinel, data=bytes(data), relaxed=True)
        except self._olevba.FileOpenError:
            raise ValueError('Input data not recognized by VBA parser')
        for p1, stream_path, p2, code in parser.extract_all_macros():
            code: str
            if not stream_path:
                if p1 == sentinel:
                    continue
                if p2 == sentinel:
                    continue
            yield UnpackResult(stream_path, code.encode(self.codec))

    @classmethod
    def handles(cls, data):
        if data[:8] == b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':
            return True
        if data[:2] == B'PK':
            return buffer_contains(data, B'xl/vbaProject.bin')
        return any(buffer_contains(data, ns) for ns in [
            b'http://schemas.microsoft.com/office/word/2003/wordml',
            b'http://schemas.microsoft.com/office/2006/xmlPackage',
        ])
