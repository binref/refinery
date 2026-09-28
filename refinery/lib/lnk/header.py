from __future__ import annotations

from datetime import datetime
from uuid import UUID

from refinery.lib.dt import filetime
from refinery.lib.lnk.flags import (
    FileAttributeFlags,
    HotKeyHigh,
    HotKeyLow,
    LinkFlags,
    ShowCommand,
)
from refinery.lib.structures import Struct, StructReader, struct_to_json

_LNK_CLSID = UUID('00021401-0000-0000-C000-000000000046')


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
        self.creation_time = filetime(reader.u64())
        self.accessed_time = filetime(reader.u64())
        self.modified_time = filetime(reader.u64())
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
                result[key] = value.isoformat(' ', 'seconds')
            else:
                result[key] = struct_to_json(value)
        return result
