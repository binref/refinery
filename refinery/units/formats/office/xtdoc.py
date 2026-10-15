from __future__ import annotations

from refinery.lib.id import is_likely_doc
from refinery.lib.ole.file import DirectoryEntry, OleFile
from refinery.lib.types import Iterable, buf
from refinery.units.formats import PathExtractorUnit, UnpackResult
from refinery.units.formats.archive.xtzip import xtzip

_MSI_NAME_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._'


def convert_msi_name(name: str):
    def _decode(alphabet=F'{_MSI_NAME_ALPHABET}!'):
        for character in name:
            code = ord(character)
            if 0x3800 <= code < 0x4800:
                yield alphabet[(code - 0x3800) & 0x3F] + alphabet[((code - 0x3800) >> 6) & 0x3F]
            elif 0x4800 <= code <= 0x4840:
                yield alphabet[code - 0x4800]
            else:
                yield character
    return ''.join(_decode())


def msi_table_stream_name(table: str) -> str:
    """
    The name of the stream in the compound file that holds the given table of an MSI database. The
    Windows Installer opens a table only under this name, but `convert_msi_name` decodes other names
    to the same text.
    """
    encoded = [chr(0x4840)]
    position = 0
    while position < len(table):
        first = _MSI_NAME_ALPHABET.find(table[position])
        second = -1
        if position + 1 < len(table):
            second = _MSI_NAME_ALPHABET.find(table[position + 1])
        if first < 0:
            encoded.append(table[position])
            position += 1
        elif second < 0:
            encoded.append(chr(0x4800 + first))
            position += 1
        else:
            encoded.append(chr(0x3800 + first + (second << 6)))
            position += 2
    return ''.join(encoded)


class xtdoc(PathExtractorUnit):
    """
    Extract embedded files from an OLE document such as a Microsoft Word DOCX file.
    """

    def _streams(self, document: OleFile) -> Iterable[tuple[DirectoryEntry, UnpackResult]]:
        """
        Generates every stream of the given compound file as its directory entry together with the
        result that hands it out under its decoded path.
        """
        for item, entry in document.walk():
            if not item or not item[-1]:
                continue
            stream = document.openentry(entry)
            c0 = ord(item[-1][:1])
            if c0 < 20:
                item[-1] = F'[{c0:d}]{item[-1][1:]}'
            path = convert_msi_name('/'.join(item))
            self.log_debug('exploring:', path)
            yield entry, UnpackResult(path, stream.read())

    def unpack(self, data: buf):
        try:
            document = OleFile(data)
        except OSError as error:
            self.log_info(F'error, {error}, treating input as zip file')
            yield from xtzip().unpack(data)
            return
        for _, result in self._streams(document):
            yield result

    @classmethod
    def handles(cls, data) -> bool | None:
        if data[:8] == B'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':
            return True
        return is_likely_doc(data)
