#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Optional
from uuid import UUID

from refinery import Unit
from refinery.lib.structures import Struct, StructReader


class FileDataStoreObject(Struct):
    MAGIC = UUID('e716e3bd-6526-1145-a4c4-8d4d0b7a9eac').bytes

    def __init__(self, reader: StructReader):
        if reader.read(16) != self.MAGIC:
            raise ValueError('invalid GUID at the beginning of FileDataStoreObject')
        self.size = reader.u64()
        reader.u32()  # reserved
        reader.u64()  # unused
        self.data = reader.read(self.size)
        reader.byte_align(8)
        if UUID(bytes=bytes(reader.read(16))) != UUID('22a7fb71-790f-0b4a-bb13-899256426b24'):
            raise ValueError('invalid GUID at the end of FileDataStoreObject')
        self.end = reader.tell()


class xtone(Unit):
    """
    Extract embedded files from OneNote documents.
    """

    def process(self, data: bytearray):
        position = 0
        view = memoryview(data)
        while True:
            position = data.find(FileDataStoreObject.MAGIC, position)
            if position < 0:
                break
            try:
                object = FileDataStoreObject(view[position:])
            except Exception as error:
                self.log_warn(F'error parsing structure at offset 0x{position:X}: {error!s}')
                position += 1
            else:
                yield object.data
            finally:
                position += object.end

    @classmethod
    def handles(cls, data: bytearray) -> Optional[bool]:
        return UUID('e4525c7b-8cd8-a74d-aeb1-5378d02996d3').bytes in data
