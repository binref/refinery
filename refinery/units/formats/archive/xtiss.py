#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Optional
from itertools import cycle, islice

import zlib

from refinery.units.formats.archive import ArchiveUnit
from refinery.lib.structures import StructReader


class ISSReader(StructReader[bytearray]):

    MAGIC = {
        b'InstallShield\0': 1,
        b'ISSetupStream\0': 2,
    }

    def iss_archive_header(self):
        signature = bytes(self.read(14))
        try:
            self.__version = self.MAGIC[signature]
        except KeyError:
            raise ValueError('invalid signature for ISS archive')
        file_count = self.u16()
        self.seekrel(0x04)
        self.seekrel(0x08)
        self.seekrel(0x02)
        self.seekrel(0x10)
        return file_count

    def iss_file_header(self):
        if self.__version == 1:
            name = self.read(260).rstrip(B'\0').decode('utf8')
            flags = self.u32()
            self.seekrel(4)
            size = self.u32()
            self.seekrel(8)
            is_unicode = self.u16()
            self.seekrel(30)
        else:
            name_length = self.u32()
            flags = self.u32()
            self.seekrel(2)
            size = self.u32()
            self.seekrel(8)
            is_unicode = self.u16()
            name = self.read(name_length).decode('utf-16le')
        return name, size, flags, is_unicode

    def iss_file(self):
        name, size, flags, is_unicode = self.iss_file_header()

        def _data(
            data: bytearray = self.read(size),
            seed: bytes = name.encode('utf8'),
            _is4: bool = flags & 4 == 4,
            _isu: bool = is_unicode
        ):
            key = bytes(x ^ k for x, k in zip(seed, cycle(B'\x13\x35\x86\x07')))
            if _is4:
                key = bytes(islice(cycle(key), 0, 1024))
            for (i, b), k in zip(enumerate(data), cycle(key)):
                data[i] = ~(k ^ (b << 4 | b >> 4)) & 0xFF
            if _isu:
                data = zlib.decompress(data)
            return data
        return name, _data


class xtiss(ArchiveUnit):
    """
    Extracts files from Install Shield Setup files.
    """
    def unpack(self, data: bytearray):
        offset = max(data.rfind(magic) for magic in ISSReader.MAGIC)
        if offset < 0:
            raise ValueError('ISS magic not found.')
        data[:offset] = []

        reader = ISSReader(data)
        count = reader.iss_archive_header()

        self.log_info(F'archive contains {count} files according to header')

        for _ in range(count):
            name, data = reader.iss_file()
            yield self._pack(name, None, data)

    @classmethod
    def handles(cls, data: bytearray) -> Optional[bool]:
        return data.startswith(B'MZ') and any(data.find(m) > 0 for m in ISSReader.MAGIC)
