from __future__ import annotations

from datetime import datetime, timezone, timedelta
from uuid import UUID

from refinery.lib.lnk.flags import (
    FileAttributeFlags,
    HotKeyHigh,
    HotKeyLow,
    LinkFlags,
    ShowCommand,
)
from refinery.lib.structures import Struct, StructReader, struct_to_json

_LNK_CLSID = UUID('00021401-0000-0000-C000-000000000046')
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _filetime_to_datetime(ft: int) -> datetime | None:
    if ft == 0:
        return None
    try:
        dt = _FILETIME_EPOCH + timedelta(microseconds=ft // 10)
        return dt.replace(microsecond=0)
    except (OverflowError, OSError, ValueError):
        return None


class ShellLinkHeader(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview]):
        self.header_size = reader.u32()
        if self.header_size != 0x4C:
            raise ValueError(
                F'invalid LNK header size: 0x{self.header_size:X}')
        self.clsid = reader.read_guid()
        if self.clsid != _LNK_CLSID:
            raise ValueError(
                F'invalid LNK CLSID: {self.clsid}')
        self.link_flags = LinkFlags(reader.u32())
        self.file_attributes = FileAttributeFlags(reader.u32())
        self.creation_time = _filetime_to_datetime(reader.u64())
        self.accessed_time = _filetime_to_datetime(reader.u64())
        self.modified_time = _filetime_to_datetime(reader.u64())
        self.file_size = reader.u32()
        self.icon_index = reader.i32()
        raw_show = reader.u32()
        try:
            self.show_command = ShowCommand(raw_show)
        except ValueError:
            self.show_command = ShowCommand.Normal
        hot_key_low = reader.u8()
        hot_key_high = reader.u8()
        try:
            self.hot_key_low = HotKeyLow(hot_key_low)
        except ValueError:
            self.hot_key_low = HotKeyLow.Unset
        self.hot_key_high = HotKeyHigh(hot_key_high)
        reader.skip(10)

    def __json__(self) -> dict:
        result = {}
        for key, value in self.__dict__.items():
            if key.startswith('_'):
                continue
            if key == 'clsid':
                result[key] = str(value)
            elif isinstance(value, datetime):
                result[key] = str(value)
            else:
                result[key] = struct_to_json(value)
        return result
