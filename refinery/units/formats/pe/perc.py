#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import TYPE_CHECKING

import enum
import re
import struct

from refinery.units.formats import UnpackResult, PathExtractorUnit, Arg
from refinery.lib.structures import Struct, StructReader, MemoryFile

if TYPE_CHECKING:
    from refinery.lib.types import ByteStr
    from typing import Tuple, Callable


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
        def fixpath(p: str):
            if kwargs.get('regex', False) or not p.isidentifier():
                return p
            return re.compile(FR'^.*?{re.escape(p)}.*$')
        super().__init__(*(fixpath(p) for p in paths), pretty=pretty, **kwargs)

    @PathExtractorUnit.Requires('lief')
    def _lief():
        import lief
        return lief

    def _get_icon_dir(self, pe):
        for manifest_entry in pe.resources.childs:
            if manifest_entry.id != RSRC.ICON_GROUP.value:
                continue
            return GRPICONDIR(bytearray(manifest_entry.childs[0].childs[0].content))

    def _search(self, pe, directory, *parts):
        if directory.depth >= 3:
            self.log_warn(F'unexpected resource tree level {directory.depth + 1:d}')
        for entry in directory.childs:
            if entry.has_name:
                identifier = str(entry.name)
            elif directory.depth == 0 and entry.id in iter(RSRC):
                identifier = RSRC(entry.id)
            elif entry.id is not None:
                identifier = entry.id
            else:
                self.log_warn(F'resource entry has name {entry.name} and id {entry.id} at level {directory.depth + 1:d}')
                continue
            if entry.is_directory:
                yield from self._search(pe, entry, *parts, identifier)
            else:
                def extract(_=pe, e=entry):
                    return bytearray(e.content)
                path = '/'.join(str(p) for p in (*parts, identifier))
                if self.args.pretty:
                    if parts[0] is RSRC.BITMAP:
                        extract = self._handle_bitmap(extract)
                    elif parts[0] is RSRC.ICON:
                        extract = self._handle_icon(pe, extract, parts)
                yield UnpackResult(path, extract, offset=entry.offset)

    def _handle_bitmap(self, extract_raw_data: Callable[[], ByteStr]) -> ByteStr:
        def extract():
            bitmap = extract_raw_data()
            total = (len(bitmap) + 14).to_bytes(4, 'little')
            return B'BM' + total + B'\0\0\0\0\x36\0\0\0' + bitmap
        return extract

    def _handle_icon(self, pe, extract_raw_data: Callable[[], ByteStr], parts: Tuple[RSRC, int, int]) -> ByteStr:
        try:
            icondir = self._get_icon_dir(pe)
            index = int(parts[1]) - 1
            info = icondir.entries[index]
        except Exception as E:
            self.log_warn(F'unable to generate icon header: {E!s}')
            return extract_raw_data

        def extract(info=info):
            icon = extract_raw_data()
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

        return extract

    def unpack(self, data):
        with MemoryFile(data) as mf:
            pe = self._lief.PE.parse(mf)
        if not pe.has_resources:
            return
        yield from self._search(pe, pe.resources)
