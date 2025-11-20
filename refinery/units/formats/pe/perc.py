from __future__ import annotations

import enum
import struct

from typing import Callable

from refinery.lib import json, lief
from refinery.lib.lcid import LCID
from refinery.lib.structures import Struct, StructReader
from refinery.lib.types import Param, buf
from refinery.units.formats import Arg, PathExtractorUnit, UnpackResult


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


_RSRC = set(RSRC)


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


def _mktbl(ids: list[tuple[int, int, int]]) -> dict[int, dict[int, int]]:
    table = {}
    for pid, sid, lcid in ids:
        if pid not in table:
            table[pid] = {0: lcid}
        table[pid][sid] = lcid
    return table


class perc(PathExtractorUnit):
    """
    Extract PE file resources.
    """
    def __init__(
        self, *paths,
        pretty: Param[bool, Arg.Switch('-p', help='Add missing headers to bitmap and icon resources.')] = False,
        **kwargs
    ):
        super().__init__(*paths, pretty=pretty, **kwargs)

    def _get_icon_dir(self, pe: lief.PE.Binary):
        for manifest_entry in pe.resources.childs:
            if manifest_entry.id != RSRC.ICON_GROUP.value:
                continue
            child = manifest_entry.childs[0].childs[0]
            if isinstance(child, lief.PE.ResourceData):
                return GRPICONDIR.Parse(bytearray(child.content))

    def _search(self, pe: lief.PE.Binary, directory: lief.PE.ResourceDirectory, *parts):
        if directory.depth >= 3:
            self.log_warn(F'unexpected resource tree level {directory.depth + 1:d}')
        for entry in directory.childs:
            if entry.has_name:
                identifier = str(entry.name)
            elif directory.depth == 0 and entry.id in _RSRC:
                identifier = RSRC(entry.id)
            elif entry.id is not None:
                identifier = entry.id
            else:
                self.log_warn(F'resource entry has name {entry.name} and id {entry.id} at level {directory.depth + 1:d}')
                continue
            if isinstance(entry, lief.PE.ResourceDirectory):
                yield from self._search(pe, entry, *parts, identifier)
                continue
            if isinstance(entry, lief.PE.ResourceData):
                def _extract_raw_data(_=pe, e=entry):
                    return bytearray(e.content)
                extract: buf | Callable[[], buf] = _extract_raw_data
                path = '/'.join(str(p) for p in (*parts, identifier))
                if self.args.pretty:
                    if parts[0] is RSRC.BITMAP:
                        extract = self._handle_bitmap(extract)
                    elif parts[0] is RSRC.ICON:
                        extract = self._handle_icon(pe, extract, parts)
                    elif parts[0] is RSRC.ICON_GROUP:
                        def _extract_ico_grp(_=pe, e=entry):
                            data = GRPICONDIR.Parse(e.content)
                            return json.dumps({
                                entry.nid: {
                                    'width'         : entry.width,
                                    'height'        : entry.height,
                                    'bytes'         : entry.bytes_in_res,
                                    'color'         : {
                                        'count'     : entry.color_count,
                                        'planes'    : entry.planes,
                                        'bits'      : entry.bit_count,
                                    },
                                } for entry in data.entries},
                            )
                        extract = _extract_ico_grp

                yield UnpackResult(
                    path,
                    extract,
                    lcid=self._get_lcid(entry),
                    offset=entry.offset,
                )

    def _get_lcid(self, node_data) -> str | None:
        try:
            pid = node_data.id & 0x3FF
            sid = node_data.id >> 0x0A
        except AttributeError:
            return None
        try:
            pid = self._LANG_ID_TO_LCID[pid]
        except KeyError:
            return None
        lcid = pid.get(sid, 0)
        return LCID.get(lcid)

    def _handle_bitmap(self, extract_raw_data: Callable[[], buf]) -> Callable[[], buf]:
        def extract():
            bitmap = extract_raw_data()
            total = (len(bitmap) + 14).to_bytes(4, 'little')
            return B'BM' + total + B'\0\0\0\0\x36\0\0\0' + bitmap
        return extract

    def _handle_icon(
        self,
        pe: lief.PE.Binary,
        extract_raw_data: Callable[[], buf],
        parts: tuple[RSRC, int, int]
    ) -> buf | Callable[[], buf]:
        try:
            icondir = self._get_icon_dir(pe)
            if icondir is None:
                raise RuntimeError
            index = int(parts[1]) - 1
            info = icondir.entries[index]
        except IndexError:
            return extract_raw_data
        except Exception as E:
            self.log_warn(F'unable to generate icon header: {E!s}')
            return extract_raw_data

        def extract(info=info):
            icon = extract_raw_data()
            if icon[:4] == B'\x28\0\0\0':
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
        pe = lief.load_pe_fast(data, parse_rsrc=True)
        if not pe.has_resources:
            return
        if not isinstance(rsrc := pe.resources, lief.PE.ResourceDirectory):
            raise TypeError('resource root entry was unexpectedly not a directory')
        yield from self._search(pe, rsrc)

    _LANG_ID_TO_LCID = _mktbl([
        (0x00, 0x03, 0x0C00),
        (0x00, 0x05, 0x1400),
        (0x7F, 0x00, 0x007F),
        (0x00, 0x00, 0x0000),
        (0x02, 0x02, 0x0800),
        (0x00, 0x04, 0x1000),
        (0x00, 0x01, 0x0400),
        (0x36, 0x01, 0x0436),
        (0x1c, 0x01, 0x041C),
        (0x84, 0x01, 0x0484),
        (0x5E, 0x01, 0x045E),
        (0x01, 0x05, 0x1401),
        (0x01, 0x0f, 0x3C01),
        (0x01, 0x03, 0x0C01),
        (0x01, 0x02, 0x0801),
        (0x01, 0x0B, 0x2C01),
        (0x01, 0x0D, 0x3401),
        (0x01, 0x0C, 0x3001),
        (0x01, 0x04, 0x1001),
        (0x01, 0x06, 0x1801),
        (0x01, 0x08, 0x2001),
        (0x01, 0x10, 0x4001),
        (0x01, 0x01, 0x0401),
        (0x01, 0x0A, 0x2801),
        (0x01, 0x07, 0x1C01),
        (0x01, 0x0E, 0x3801),
        (0x01, 0x09, 0x2401),
        (0x2B, 0x01, 0x042B),
        (0x4D, 0x01, 0x044D),
        (0x2C, 0x02, 0x082C),
        (0x2C, 0x01, 0x042C),
        (0x45, 0x02, 0x0445),
        (0x6D, 0x01, 0x046D),
        (0x2d, 0x01, 0x042D),
        (0x23, 0x01, 0x0423),
        (0x1A, 0x08, 0x201A),
        (0x1A, 0x05, 0x141A),
        (0x7E, 0x01, 0x047E),
        (0x02, 0x01, 0x0402),
        (0x92, 0x01, 0x0492),
        (0x5C, 0x01, 0x045C),
        (0x03, 0x01, 0x0403),
        (0x04, 0x03, 0x0C04),
        (0x04, 0x05, 0x1404),
        (0x04, 0x04, 0x1004),
        (0x04, 0x02, 0x0004),
        (0x04, 0x01, 0x7C04),
        (0x83, 0x01, 0x0483),
        (0x1A, None, 0x001A),
        (0x1a, 0x04, 0x101A),
        (0x1a, 0x01, 0x041A),
        (0x05, 0x01, 0x0405),
        (0x06, 0x01, 0x0406),
        (0x8C, 0x01, 0x048C),
        (0x65, 0x01, 0x0465),
        (0x13, 0x02, 0x0813),
        (0x13, 0x01, 0x0413),
        (0x09, 0x03, 0x0C09),
        (0x09, 0x0A, 0x2809),
        (0x09, 0x04, 0x1009),
        (0x09, 0x09, 0x2409),
        (0x09, 0x10, 0x4009),
        (0x09, 0x06, 0x1809),
        (0x09, 0x08, 0x2009),
        (0x09, 0x11, 0x4409),
        (0x09, 0x05, 0x1409),
        (0x09, 0x0D, 0x3409),
        (0x09, 0x12, 0x4809),
        (0x09, 0x07, 0x1c09),
        (0x09, 0x0B, 0x2C09),
        (0x09, 0x02, 0x0809),
        (0x09, 0x01, 0x0409),
        (0x09, 0x0C, 0x3009),
        (0x25, 0x01, 0x0425),
        (0x38, 0x01, 0x0438),
        (0x64, 0x01, 0x0464),
        (0x0B, 0x01, 0x040B),
        (0x0C, 0x02, 0x080c),
        (0x0C, 0x03, 0x0C0C),
        (0x0C, 0x01, 0x040c),
        (0x0C, 0x05, 0x140C),
        (0x0C, 0x06, 0x180C),
        (0x0C, 0x04, 0x100C),
        (0x62, 0x01, 0x0462),
        (0x56, 0x01, 0x0456),
        (0x37, 0x01, 0x0437),
        (0x07, 0x03, 0x0C07),
        (0x07, 0x01, 0x0407),
        (0x07, 0x05, 0x1407),
        (0x07, 0x04, 0x1007),
        (0x07, 0x02, 0x0807),
        (0x08, 0x01, 0x0408),
        (0x6F, 0x01, 0x046F),
        (0x47, 0x01, 0x0447),
        (0x68, 0x01, 0x0468),
        (0x75, 0x01, 0x0475),
        (0x0D, 0x01, 0x040D),
        (0x39, 0x01, 0x0439),
        (0x0E, 0x01, 0x040E),
        (0x0F, 0x01, 0x040F),
        (0x70, 0x01, 0x0470),
        (0x21, 0x01, 0x0421),
        (0x5D, 0x02, 0x085D),
        (0x5D, 0x01, 0x045D),
        (0x3C, 0x02, 0x083C),
        (0x34, 0x01, 0x0434),
        (0x35, 0x01, 0x0435),
        (0x10, 0x01, 0x0410),
        (0x10, 0x02, 0x0810),
        (0x11, 0x01, 0x0411),
        (0x4B, 0x01, 0x044B),
        (0x3F, 0x01, 0x043F),
        (0x53, 0x01, 0x0453),
        (0x86, 0x01, 0x0486),
        (0x87, 0x01, 0x0487),
        (0x57, 0x01, 0x0457),
        (0x12, 0x01, 0x0412),
        (0x40, 0x01, 0x0440),
        (0x54, 0x01, 0x0454),
        (0x26, 0x01, 0x0426),
        (0x27, 0x01, 0x0427),
        (0x2E, 0x02, 0x082E),
        (0x6E, 0x01, 0x046E),
        (0x2F, 0x01, 0x042F),
        (0x3E, 0x02, 0x083E),
        (0x3E, 0x01, 0x043e),
        (0x4C, 0x01, 0x044C),
        (0x3A, 0x01, 0x043A),
        (0x81, 0x01, 0x0481),
        (0x7A, 0x01, 0x047A),
        (0x4E, 0x01, 0x044E),
        (0x7C, 0x01, 0x047C),
        (0x50, 0x01, 0x0450),
        (0x50, 0x02, 0x0850),
        (0x61, 0x01, 0x0461),
        (0x14, 0x01, 0x0414),
        (0x14, 0x02, 0x0814),
        (0x82, 0x01, 0x0482),
        (0x48, 0x01, 0x0448),
        (0x63, 0x01, 0x0463),
        (0x29, 0x01, 0x0429),
        (0x15, 0x01, 0x0415),
        (0x16, 0x01, 0x0416),
        (0x16, 0x02, 0x0816),
        (0x67, 0x02, 0x0867),
        (0x46, 0x01, 0x0446),
        (0x46, 0x02, 0x0846),
        (0x6B, 0x01, 0x046B),
        (0x6B, 0x02, 0x086B),
        (0x6B, 0x03, 0x0C6B),
        (0x18, 0x01, 0x0418),
        (0x17, 0x01, 0x0417),
        (0x19, 0x01, 0x0419),
        (0x85, 0x01, 0x0485),
        (0x3B, 0x09, 0x243B),
        (0x3B, 0x04, 0x103B),
        (0x3B, 0x05, 0x143B),
        (0x3B, 0x03, 0x0C3B),
        (0x3B, 0x01, 0x043B),
        (0x3B, 0x02, 0x083B),
        (0x3B, 0x08, 0x203B),
        (0x3B, 0x06, 0x183B),
        (0x3B, 0x07, 0x1C3B),
        (0x4F, 0x01, 0x044F),
        (0x1a, 0x07, 0x1C1A),
        (0x1a, 0x06, 0x181A),
        (0x1a, 0x03, 0x0C1A),
        (0x1a, 0x02, 0x081A),
        (0x6C, 0x01, 0x046C),
        (0x32, 0x02, 0x0832),
        (0x32, 0x01, 0x0432),
        (0x32, 0x01, 0x0459),
        (0x32, 0x02, 0x0859),
        (0x5B, 0x01, 0x045B),
        (0x1b, 0x01, 0x041B),
        (0x24, 0x01, 0x0424),
        (0x0A, 0x0b, 0x2C0A),
        (0x0A, 0x10, 0x400A),
        (0x0A, 0x0D, 0x340A),
        (0x0A, 0x09, 0x240A),
        (0x0A, 0x05, 0x140A),
        (0x0A, 0x07, 0x1C0A),
        (0x0A, 0x0C, 0x300A),
        (0x0A, 0x11, 0x440A),
        (0x0A, 0x04, 0x100A),
        (0x0A, 0x12, 0x480A),
        (0x0A, 0x02, 0x080A),
        (0x0A, 0x13, 0x4C0A),
        (0x0A, 0x06, 0x180A),
        (0x0A, 0x0F, 0x3C0A),
        (0x0A, 0x0A, 0x280A),
        (0x0A, 0x14, 0x500A),
        (0x0A, 0x03, 0x0C0A),
        (0x0A, 0x01, 0x040A),
        (0x0A, 0x15, 0x540A),
        (0x0A, 0x0E, 0x380A),
        (0x0A, 0x08, 0x200A),
        (0x41, 0x01, 0x0441),
        (0x1D, 0x02, 0x081D),
        (0x1D, 0x01, 0x041D),
        (0x5A, 0x01, 0x045A),
        (0x28, 0x01, 0x0428),
        (0x5F, 0x02, 0x085F),
        (0x49, 0x01, 0x0449),
        (0x49, 0x02, 0x0849),
        (0x44, 0x01, 0x0444),
        (0x4A, 0x01, 0x044A),
        (0x1E, 0x01, 0x041E),
        (0x51, 0x01, 0x0451),
        (0x73, 0x02, 0x0873),
        (0x73, 0x01, 0x0473),
        (0x1F, 0x01, 0x041F),
        (0x42, 0x01, 0x0442),
        (0x22, 0x01, 0x0422),
        (0x2E, 0x01, 0x042E),
        (0x20, 0x02, 0x0820),
        (0x20, 0x01, 0x0420),
        (0x80, 0x01, 0x0480),
        (0x43, 0x02, 0x0843),
        (0x43, 0x01, 0x0443),
        (0x03, 0x02, 0x0803),
        (0x2A, 0x01, 0x042A),
        (0x52, 0x01, 0x0452),
        (0x88, 0x01, 0x0488),
        (0x78, 0x01, 0x0478),
        (0x6A, 0x01, 0x046A),
    ])
