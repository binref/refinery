#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units import Unit
from refinery.lib.structures import MemoryFile


class MemoryFileRecorder(MemoryFile):

    def __init__(self, data):
        self.max_cursor = 0
        self.__cursor = 0
        super().__init__(data)

    @property
    def _cursor(self):
        return self.__cursor

    @_cursor.setter
    def _cursor(self, value):
        if value > self.max_cursor:
            self.max_cursor = value
        self.__cursor = value


class carve_7z(Unit):
    """
    Extracts anything from the input data that looks like a 7zip archive file.
    """
    @Unit.Requires('py7zr', optional=False)
    def _py7zr():
        import py7zr
        return py7zr

    HEADER_SIGNATURE = B'7z\xBC\xAF\x27\x1C'

    def process(self, data):
        cursor = 0
        mv = memoryview(data)
        while True:
            start = data.find(self.HEADER_SIGNATURE, cursor)
            if start < cursor:
                break
            try:
                mf = MemoryFileRecorder(mv[start:])
                archive = self._py7zr.SevenZipFile(mf)
                success = archive.test() is not False
            except Exception:
                success = False
            if success:
                cursor = start + mf.max_cursor
                yield mv[start:cursor]
            else:
                cursor += 5
