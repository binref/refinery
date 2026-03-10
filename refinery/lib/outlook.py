"""
Lightweight parser for Outlook MSG files based on olefile.
"""
from __future__ import annotations

import codecs
import re
import struct

from datetime import datetime, timezone, timedelta
from email.parser import HeaderParser
from functools import cached_property

_PSETID_APPOINTMENT = bytes.fromhex('0220060000000000c000000000000046')
_LID_LOCATION = 0x8208
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

_CODEPAGE_OVERRIDES = {
    20127: 'ascii',
    20932: 'euc-jp',
    28591: 'iso-8859-1',
    28592: 'iso-8859-2',
    28593: 'iso-8859-3',
    28594: 'iso-8859-4',
    28595: 'iso-8859-5',
    28596: 'iso-8859-6',
    28597: 'iso-8859-7',
    28598: 'iso-8859-8',
    28599: 'iso-8859-9',
    28603: 'iso-8859-13',
    28605: 'iso-8859-15',
    50220: 'iso-2022-jp',
    50221: 'iso-2022-jp',
    50225: 'iso-2022-kr',
    51932: 'euc-jp',
    51949: 'euc-kr',
}


def _codepage_to_codec(cp: int) -> str:
    if name := _CODEPAGE_OVERRIDES.get(cp):
        return name
    try:
        return codecs.lookup(F'cp{cp}').name
    except LookupError:
        return 'cp1252'


def _filetime_to_datetime(filetime: int) -> datetime | None:
    if filetime <= 0:
        return None
    return _FILETIME_EPOCH + timedelta(microseconds=filetime // 10)


class MsgAttachment:
    def __init__(self, ole, prefix: str, parent: MsgFile):
        self._ole = ole
        self._prefix = prefix
        self._parent = parent
        props_path = F'{prefix}/__properties_version1.0'
        self._props = parent._parse_properties(props_path, header_size=8)

    def _stream(self, path: str) -> bytes | memoryview | None:
        full = F'{self._prefix}/{path}'
        if self._ole.exists(full):
            return self._ole.openstream(full).read()
        return None

    def _read_string(self, prop_id: str) -> str | None:
        for suffix, codec in (('001F', 'utf-16-le'), ('001E', self._parent._ansi_codec)):
            data = self._stream(F'__substg1.0_{prop_id}{suffix}')
            if data is not None:
                return codecs.decode(data, codec).rstrip('\0')
        return None

    @cached_property
    def attach_method(self) -> int:
        return self._props.get('37050003', 1)

    @cached_property
    def content_id(self) -> str | None:
        return self._read_string('3712')

    @cached_property
    def mime_type(self) -> str | None:
        return self._read_string('370E')

    @cached_property
    def is_embedded_msg(self) -> bool:
        return self.attach_method == 5

    @cached_property
    def is_ole_storage(self) -> bool:
        return self.attach_method == 6

    @cached_property
    def data(self) -> bytes | memoryview | MsgFile:
        method = self.attach_method
        if method == 5:
            prefix = F'{self._prefix}/__substg1.0_3701000D'
            if self._ole.exists(prefix):
                return MsgFile._from_ole(self._ole, prefix)
        if method == 6:
            binary = self._stream('__substg1.0_37010102')
            if binary is not None:
                return binary
        if method in (2, 3, 4, 7):
            ref = self._read_string('3701') or self.long_filename
            if ref:
                return ref.encode('utf-8')
            return b''
        raw = self._stream('__substg1.0_37010102')
        return raw if raw is not None else b''

    @cached_property
    def long_filename(self) -> str | None:
        return self._read_string('3707')

    @cached_property
    def short_filename(self) -> str | None:
        return self._read_string('3704')


class MsgFile:
    def __init__(self, data: bytes | bytearray | memoryview):
        from refinery.lib.ole.file import OleFile
        from refinery.lib.structures import MemoryFile
        self._ole = OleFile(MemoryFile(data))
        self._prefix = ''
        self._init()

    @classmethod
    def _from_ole(cls, ole, prefix: str) -> MsgFile:
        obj = object.__new__(cls)
        obj._ole = ole
        obj._prefix = prefix
        obj._init()
        return obj

    def _init(self):
        self._unicode = False
        p = self._prefix
        for entry in self._ole.listdir():
            path = '/'.join(entry)
            if path.startswith(p) and path.endswith('001F'):
                self._unicode = True
                break
        props_path = F'{p}/__properties_version1.0' if p else '__properties_version1.0'
        header_size = 32 if not p else 24
        self._props = self._parse_properties(props_path, header_size)
        cp = self._props.get('3FFD0003') or self._props.get('3FDE0003')
        self._ansi_codec = _codepage_to_codec(cp) if cp else 'cp1252'
        self._named_props = self._parse_named_properties()

    def _read_stream(self, path: str) -> bytes | memoryview | None:
        if self._ole.exists(path):
            return self._ole.openstream(path).read()
        return None

    def _read_string(self, prop_id: str) -> str | None:
        p = self._prefix
        base = F'{p}/__substg1.0_{prop_id}' if p else F'__substg1.0_{prop_id}'
        for suffix, codec in (('001F', 'utf-16-le'), ('001E', self._ansi_codec)):
            data = self._read_stream(F'{base}{suffix}')
            if data is not None:
                try:
                    return codecs.decode(data, codec).rstrip('\0')
                except (UnicodeDecodeError, LookupError):
                    continue
        return None

    def _read_binary(self, prop_id: str) -> bytes | memoryview | None:
        p = self._prefix
        path = F'{p}/__substg1.0_{prop_id}0102' if p else F'__substg1.0_{prop_id}0102'
        return self._read_stream(path)

    def _parse_named_properties(self) -> dict[tuple[bytes, int], int]:
        """
        Parse the __nameid_version1.0 streams to build a mapping from (GUID, LID) to the runtime
        property ID in the 0x8000+ range.
        """
        result: dict[tuple[bytes, int], int] = {}
        guid_stream = self._read_stream('__nameid_version1.0/__substg1.0_00020102')
        data_stream = self._read_stream('__nameid_version1.0/__substg1.0_00030102')
        if not guid_stream or not data_stream:
            return result
        guids: list[bytes] = []
        for i in range(0, len(guid_stream), 16):
            guids.append(bytes(guid_stream[i:i + 16]))
        for i in range(0, len(data_stream) - 7, 8):
            lid, info, _idx = struct.unpack_from('<IHH', data_stream, i)
            is_string = info & 1
            if is_string:
                continue
            guid_idx = info >> 1
            if guid_idx < 3 or guid_idx - 3 >= len(guids):
                continue
            guid = guids[guid_idx - 3]
            result[(guid, lid)] = 0x8000 + i // 8
        return result

    def _resolve_named_prop(self, guid: bytes, lid: int) -> str | None:
        prop_id = self._named_props.get((guid, lid))
        if prop_id is not None:
            return F'{prop_id:04X}'
        return None

    def _parse_properties(self, stream_path: str, header_size: int = 32) -> dict:
        data = self._read_stream(stream_path)
        if not data or len(data) < header_size + 16:
            return {}
        props = {}
        mv = memoryview(data)
        for offset in range(header_size, len(data) - 15, 16):
            record = mv[offset:offset + 16]
            prop_type = int.from_bytes(record[0:2], 'little')
            prop_id = int.from_bytes(record[2:4], 'little')
            tag = F'{prop_id:04X}{prop_type:04X}'
            if prop_type == 0x0003:
                props[tag] = int.from_bytes(record[8:12], 'little')
            elif prop_type == 0x0040:
                ft = int.from_bytes(record[8:16], 'little')
                props[tag] = _filetime_to_datetime(ft)
        return props

    @cached_property
    def subject(self) -> str | None:
        return self._read_string('0037')

    @cached_property
    def message_class(self) -> str:
        return (self._read_string('001A') or 'IPM.Note').upper()

    @cached_property
    def sender(self) -> str | None:
        return self._read_string('0C1A') or self._read_string('0065')

    @cached_property
    def to(self) -> str | None:
        return self._read_string('0E04')

    @cached_property
    def cc(self) -> str | None:
        return self._read_string('0E03')

    @cached_property
    def bcc(self) -> str | None:
        return self._read_string('0E02')

    @cached_property
    def message_id(self) -> str | None:
        return self._read_string('1035')

    @cached_property
    def date(self) -> datetime | None:
        return self._props.get('0E060040') or self._props.get('00390040')

    @cached_property
    def header(self) -> dict[str, str]:
        raw = self._read_string('007D')
        if not raw:
            return {}
        parsed = HeaderParser().parsestr(raw)
        return dict(parsed.items())

    @cached_property
    def body(self) -> str | None:
        return self._read_string('1000')

    @cached_property
    def html_body(self) -> bytes | None:
        return self._read_binary('1013')

    @cached_property
    def rtf_body(self) -> bytes | None:
        data = self._read_binary('1009')
        if data is None:
            return None
        from refinery.lib.rtfc import decompress
        return decompress(data)

    @cached_property
    def attachments(self) -> list[MsgAttachment]:
        result = []
        p = self._prefix
        prefix_parts = p.split('/') if p else []
        depth = len(prefix_parts)
        seen = set()
        for entry in self._ole.listdir():
            if entry[:depth] != prefix_parts:
                continue
            if len(entry) <= depth:
                continue
            dirname = entry[depth]
            if not re.match(
                r'__attach_version1\.0_#[0-9A-F]{8}\Z', dirname, re.IGNORECASE
            ):
                continue
            full = '/'.join(prefix_parts + [dirname]) if p else dirname
            if full not in seen:
                seen.add(full)
                result.append(MsgAttachment(self._ole, full, self))
        return result

    # Contact properties (IPM.Contact)

    @cached_property
    def display_name(self) -> str | None:
        return self._read_string('3001')

    @cached_property
    def company(self) -> str | None:
        return self._read_string('3A16')

    @cached_property
    def job_title(self) -> str | None:
        return self._read_string('3A17')

    @cached_property
    def business_phone(self) -> str | None:
        return self._read_string('3A08')

    @cached_property
    def home_phone(self) -> str | None:
        return self._read_string('3A09')

    @cached_property
    def mobile_phone(self) -> str | None:
        return self._read_string('3A1C')

    @cached_property
    def start_time(self) -> datetime | None:
        return self._props.get('00600040')

    @cached_property
    def end_time(self) -> datetime | None:
        return self._props.get('00610040')

    @cached_property
    def location(self) -> str | None:
        prop_id = self._resolve_named_prop(_PSETID_APPOINTMENT, _LID_LOCATION)
        if prop_id:
            return self._read_string(prop_id)
        return None
