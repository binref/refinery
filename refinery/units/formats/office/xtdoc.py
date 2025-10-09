from __future__ import annotations

from refinery.lib.id import is_likely_doc
from refinery.lib.structures import MemoryFile
from refinery.units.formats import PathExtractorUnit, UnpackResult
from refinery.units.formats.archive.xtzip import xtzip


def convert_msi_name(name: str):
    def _decode(alphabet='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._!'):
        for character in name:
            code = ord(character)
            if 0x3800 <= code < 0x4800:
                yield alphabet[(code - 0x3800) & 0x3F] + alphabet[((code - 0x3800) >> 6) & 0x3F]
            elif 0x4800 <= code <= 0x4840:
                yield alphabet[code - 0x4800]
            else:
                yield character
    return ''.join(_decode())


class xtdoc(PathExtractorUnit):
    """
    Extract files from an OLE document such as a Microsoft Word DOCX file.
    """

    @PathExtractorUnit.Requires('olefile', ['formats', 'office', 'extended'])
    def _olefile():
        import olefile
        return olefile

    def unpack(self, data):
        with MemoryFile(data) as stream:
            try:
                oledoc = self._olefile.OleFileIO(stream)
            except OSError as error:
                self.log_info(F'error, {error}, treating input as zip file')
                yield from xtzip().unpack(data)
                return
            for item in oledoc.listdir():
                if not item or not item[-1]:
                    continue
                path = '/'.join(item)
                olestream = oledoc.openstream(path)
                c0 = ord(item[-1][:1])
                if c0 < 20:
                    item[-1] = F'[{c0:d}]{item[-1][1:]}'
                    path = '/'.join(item)
                path = convert_msi_name(path)
                self.log_debug('exploring:', path)
                yield UnpackResult(path, olestream.read())

    @classmethod
    def handles(cls, data) -> bool | None:
        return is_likely_doc(data)
