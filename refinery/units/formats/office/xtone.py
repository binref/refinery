#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Optional
from uuid import UUID

from refinery.units.formats import PathExtractorUnit, UnpackResult
from refinery.lib.structures import MemoryFile
from refinery.lib.mime import get_cached_file_magic_info


class xtone(PathExtractorUnit):
    """
    Extract embedded files from OneNote documents.
    """
    @PathExtractorUnit.Requires('pyonenote', 'formats', 'office')
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
    def handles(cls, data: bytearray) -> Optional[bool]:
        return UUID('e4525c7b-8cd8-a74d-aeb1-5378d02996d3').bytes in data
