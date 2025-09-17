from __future__ import annotations

from uuid import UUID

from refinery.lib.mime import get_cached_file_magic_info
from refinery.lib.structures import MemoryFile
from refinery.units.formats import PathExtractorUnit, UnpackResult


class xtone(PathExtractorUnit):
    """
    Extract embedded files from OneNote documents.
    """
    @PathExtractorUnit.Requires('pyonenote', ['formats', 'office', 'extended'])
    def _pyOneNote():
        import pyOneNote
        import pyOneNote.OneDocument
        return pyOneNote.OneDocument

    def unpack(self, data: bytearray):
        with MemoryFile(memoryview(data)) as stream:
            one = self._pyOneNote.OneDocment(stream)
        for guid, file in one.get_files().items():
            chunk = file['content']
            try:
                extension = file['extension']
            except KeyError:
                extension = F'.{get_cached_file_magic_info(chunk).extension}'
            yield UnpackResult(F'{guid}{extension}', chunk)

    @classmethod
    def handles(cls, data: bytearray) -> bool | None:
        return UUID('7b5c52e4-d88c-4da7-aeb1-5378d02996d3').bytes_le in data
