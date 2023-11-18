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
    @Unit.Requires('py7zr', 'arc', 'default', 'extended')
    def _py7zr():
        import py7zr
        return py7zr

    HEADER_SIGNATURE = B'7z\xBC\xAF\x27\x1C'

    def process(self, data: bytearray):
        cursor = 0
        mv = memoryview(data)
        while True:
            start = data.find(self.HEADER_SIGNATURE, cursor)
            if start < cursor:
                break
            self.log_debug(F'found header at offset: 0x{start:08X}')
            try:
                mf = MemoryFileRecorder(mv[start:])
                self.log_debug('attempting to read archive')
                archive = self._py7zr.SevenZipFile(mf)
                self.log_debug('attempting to test archive')
                success = archive.test() is not False
            except ImportError:
                raise
            except Exception as error:
                self.log_debug('parsing archive failed:', error)
                success = False
            if success:
                self.log_info(F'identified archive of size 0x{mf.max_cursor:08X} at offset 0x{start:08X}')
                cursor = start + mf.max_cursor
                yield self.labelled(mv[start:cursor], offset=start)
            else:
                cursor = start + 5
