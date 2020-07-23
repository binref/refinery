#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import pefile

from .. import UnpackResult, PathExtractorUnit


class pesect(PathExtractorUnit):
    """
    Extract PE sections.
    """
    def unpack(self, data):
        pe = pefile.PE(data=data)
        mv = memoryview(data)
        for section in pe.sections:
            start = section.PointerToRawData
            end = start + section.SizeOfRawData
            name = section.Name.strip(B'\0').decode('latin-1')
            yield UnpackResult(name, mv[start:end])
