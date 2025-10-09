from __future__ import annotations

import re

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
    def handles(cls, data) -> bool | None:
        return re.search(
            br'\xE4\x52\x5C\x7B\x8C\xD8\xA7\x4D\xAE\xB1\x53\x78\xD0\x29\x96\xD3', data
        ) is not None
