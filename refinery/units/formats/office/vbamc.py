from __future__ import annotations

from refinery.lib.id import buffer_contains
from refinery.lib.ole.decompiler import strip_orphan_end_statements
from refinery.lib.ole.vba import FileOpenError, VBAParser
from refinery.units.formats import PathExtractorUnit, UnpackResult


class vbamc(PathExtractorUnit):
    """
    Extract VBA macro code from Office documents such as Word and Excel.
    """
    def unpack(self, data):
        try:
            parser = VBAParser(bytes(data))
        except FileOpenError:
            return
        for macro in parser.extract_all_macros():
            if not macro.stream_path:
                continue
            if code := macro.code:
                code = strip_orphan_end_statements(code)
                yield UnpackResult(macro.stream_path, code.encode(self.codec))

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
