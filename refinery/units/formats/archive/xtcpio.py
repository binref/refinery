#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from contextlib import suppress
from datetime import datetime

from ....lib.structures import EOF, Struct, StructReader

from . import ArchiveUnit


class CPIOEntry(Struct):
    def __init__(self, reader: StructReader):
        def readint(length: int):
            return int(bytes(reader.read(length * 2)), 16)
        self.signature = reader.read(6)
        if self.signature != b'070701':
            raise ValueError('invalid CPIO header signature')
        self.inode = readint(4)
        self.mode = readint(4)
        self.uid = readint(4)
        self.gid = readint(4)
        self.nlinks = readint(4)
        mtime = readint(4)
        self.mtime = datetime.utcfromtimestamp(mtime)
        self.size = readint(4)
        self.dev = readint(4), readint(4)
        self.rdev = readint(4), readint(4)
        namesize = readint(4)
        self.checksum = readint(4)
        self.name = bytes(reader.read(namesize)).decode('ascii').rstrip('\0')
        reader.byte_align(4)
        self.data = reader.read(self.size)
        reader.byte_align(4)


class xtcpio(ArchiveUnit):
    """
    Extract files from a CPIO archive.
    """
    def unpack(self, data):
        def cpio():
            with suppress(EOF): return CPIOEntry(reader)
        reader = StructReader(memoryview(data))
        for entry in iter(cpio, None):
            if entry.name == 'TRAILER!!!':
                break
            yield self._pack(entry.name, entry.mtime, entry.data)
