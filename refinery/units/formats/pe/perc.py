#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Tuple

import enum
import pefile
import re
import struct
import json

from refinery.units.formats import UnpackResult, PathExtractorUnit, Arg
from refinery.lib.structures import Struct, StructReader


class RSRC(enum.IntEnum):
    CURSOR        = 0x01  # noqa
    BITMAP        = 0x02  # noqa
    ICON          = 0x03  # noqa
    MENU          = 0x04  # noqa
    DIALOG        = 0x05  # noqa
    STRING        = 0x06  # noqa
    FONTDIR       = 0x07  # noqa
    FONT          = 0x08  # noqa
    ACCELERATOR   = 0x09  # noqa
    RCDATA        = 0x0A  # noqa
    MESSAGETABLE  = 0x0B  # noqa
    ICON_GROUP    = 0x0E  # noqa
    VERSION       = 0x10  # noqa
    DLGINCLUDE    = 0x11  # noqa
    PLUGPLAY      = 0x13  # noqa
    VXD           = 0x14  # noqa
    ANICURSOR     = 0x15  # noqa
    ANIICON       = 0x16  # noqa
    HTML          = 0x17  # noqa
    MANIFEST      = 0x18  # noqa

    def __str__(self):
        return self.name


class GRPICONDIRENTRY(Struct):
    def __init__(self, reader: StructReader):
        self.width = reader.u8()
        self.height = reader.u8()
        self.color_count = reader.u8()
        self.reserved = reader.u8()
        self.planes = reader.u16()
        self.bit_count = reader.u16()
        self.bytes_in_res = reader.u32()
        self.nid = reader.u16()


class GRPICONDIR(Struct):
    def __init__(self, reader: StructReader):
        self.reserved = reader.u16()
        self.type = reader.u16()
        count = reader.u16()
        self.entries = [GRPICONDIRENTRY(reader) for _ in range(count)]


class perc(PathExtractorUnit):
    """
    Extract PE file resources.
    """
    def __init__(
        self, *paths,
        pretty: Arg.Switch('-p', help='Add missing headers to bitmap and icon resources.') = False,
        **kwargs
    ):
        super().__init__(*paths, pretty=pretty, **kwargs)

    def _get_icon_dir(self, pe: pefile.PE):
        try:
            group, = (e for e in pe.DIRECTORY_ENTRY_RESOURCE.entries if e.id == RSRC.ICON_GROUP.value)
            group = group.directory.entries[0].directory.entries[0].data.struct
            return GRPICONDIR(pe.get_data(group.OffsetToData, group.Size))
        except Exception:
            return None

    def _search(self, pe: pefile.PE, directory, level=0, *parts):
        if level >= 3:
            self.log_warn(F'unexpected resource tree level {level + 1:d}')
        for entry in directory.entries:
            if entry.name:
                identifier = str(entry.name)
            elif level == 0 and entry.id in iter(RSRC):
                identifier = RSRC(entry.id)
            elif entry.id is not None:
                identifier = entry.id
            else:
                self.log_warn(F'resource entry has name {entry.name} and id {entry.id} at level {level + 1:d}')
                continue
            if entry.struct.DataIsDirectory:
                yield from self._search(pe, entry.directory, level + 1, *parts, identifier)
            else:
                rva = entry.data.struct.OffsetToData
                size = entry.data.struct.Size
                path = '/'.join(str(p) for p in (*parts, identifier))
                extract = None
                if self.args.pretty:
                    if parts[0] is RSRC.BITMAP:
                        extract = self._handle_bitmap(pe, rva, size)
                    elif parts[0] is RSRC.ICON:
                        extract = self._handle_icon(pe, parts, rva, size)
                    elif parts[0] is RSRC.STRING:
                        extract = self._handle_strings(pe, parts, rva, size)
                if extract is None:
                    def extract(pe=pe):
                        return pe.get_data(rva, size)
                yield UnpackResult(path, extract, offset=pe.get_offset_from_rva(rva))

    def _handle_strings(self, pe: pefile.PE, parts: Tuple[RSRC, int, int], rva: int, size: int):
        def extract(pe=pe):
            self.log_debug(parts)
            base = (parts[1] - 1) << 4
            reader = StructReader(pe.get_data(rva, size))
            table = {}
            index = 0
            while not reader.eof:
                string = reader.read_exactly(reader.u16() * 2)
                if not string:
                    break
                key = F'{base+index:04X}'
                table[key] = string.decode('utf-16le')
                index += 1
            return json.dumps(table, indent=4).encode(self.codec)
        return extract

    def _handle_bitmap(self, pe: pefile.PE, rva: int, size: int):
        def extract(pe=pe):
            bitmap = pe.get_data(rva, size)
            total = (len(bitmap) + 14).to_bytes(4, 'little')
            return B'BM' + total + B'\0\0\0\0\x36\0\0\0' + bitmap
        return extract

    def _handle_icon(self, pe: pefile.PE, parts: Tuple[RSRC, int, int], rva: int, size: int):
        try:
            icondir = self._get_icon_dir(pe)
            index = int(parts[1]) - 1
            info = icondir.entries[index]
            icon = pe.get_data(rva, size)
        except Exception:
            return None
        if icon.startswith(B'(\0\0\0'):
            header = struct.pack('<HHHBBBBHHII',
                0,
                1,
                1,
                info.width,
                info.height,
                info.color_count,
                0,
                info.planes,
                info.bit_count,
                len(icon),
                0x16
            )
            icon = header + icon
        return icon

    def unpack(self, data):
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(
            directories=pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'])
        try:
            rsrc = pe.DIRECTORY_ENTRY_RESOURCE
        except AttributeError:
            pass
        else:
            yield from self._search(pe, rsrc)
