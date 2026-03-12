from __future__ import annotations

import codecs

from refinery.lib.lnk.flags import (
    CommonNetworkRelativeLinkFlags,
    DriveType,
    LinkInfoFlags,
    NetworkProviderType,
)
from refinery.lib.structures import Struct, StructReader, struct_to_json


class VolumeID(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview]):
        start = reader.tell()
        size = reader.u32()
        raw_drive = reader.u32()
        try:
            self.drive_type = DriveType(raw_drive)
        except ValueError:
            self.drive_type = DriveType.Unknown
        self.drive_serial_number = reader.u32()
        volume_label_offset = reader.u32()
        if volume_label_offset == 0x14:
            volume_label_offset_unicode = reader.u32()
        else:
            volume_label_offset_unicode = 0
        if volume_label_offset_unicode:
            reader.seekset(start + volume_label_offset_unicode)
            self.volume_label = reader.read_w_string('utf-16-le')
        else:
            reader.seekset(start + volume_label_offset)
            raw = reader.read_c_string()
            try:
                self.volume_label = codecs.decode(raw, 'cp1252')
            except Exception:
                self.volume_label = bytes(raw).hex()
        reader.seekset(start + size)


class CommonNetworkRelativeLink(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview]):
        start = reader.tell()
        size = reader.u32()
        self.flags = CommonNetworkRelativeLinkFlags(reader.u32())
        net_name_offset = reader.u32()
        device_name_offset = reader.u32()
        raw_provider = reader.u32()
        try:
            self.network_provider_type = NetworkProviderType(raw_provider)
        except ValueError:
            self.network_provider_type = None
        if net_name_offset > 0x14:
            net_name_offset_unicode = reader.u32()
            device_name_offset_unicode = reader.u32()
        else:
            net_name_offset_unicode = 0
            device_name_offset_unicode = 0
        if net_name_offset_unicode:
            reader.seekset(start + net_name_offset_unicode)
            self.net_name = reader.read_w_string('utf-16-le')
        else:
            reader.seekset(start + net_name_offset)
            raw = reader.read_c_string()
            try:
                self.net_name = codecs.decode(raw, 'cp1252')
            except Exception:
                self.net_name = bytes(raw).hex()
        if self.flags.ValidDevice:
            if device_name_offset_unicode:
                reader.seekset(start + device_name_offset_unicode)
                self.device_name = reader.read_w_string('utf-16-le')
            else:
                reader.seekset(start + device_name_offset)
                raw = reader.read_c_string()
                try:
                    self.device_name = codecs.decode(raw, 'cp1252')
                except Exception:
                    self.device_name = bytes(raw).hex()
        else:
            self.device_name = None
        reader.seekset(start + size)


class LinkInfo(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview]):
        start = reader.tell()
        size = reader.u32()
        header_size = reader.u32()
        self.flags = LinkInfoFlags(reader.u32())
        volume_id_offset = reader.u32()
        local_base_path_offset = reader.u32()
        cnrl_offset = reader.u32()
        common_path_suffix_offset = reader.u32()
        has_unicode = header_size >= 0x24
        if has_unicode:
            local_base_path_offset_unicode = reader.u32()
            common_path_suffix_offset_unicode = reader.u32()
        else:
            local_base_path_offset_unicode = 0
            common_path_suffix_offset_unicode = 0
        self.volume_id: VolumeID | None = None
        self.local_base_path: str | None = None
        self.common_network_relative_link: CommonNetworkRelativeLink | None = None
        self.common_path_suffix: str | None = None
        if self.flags.VolumeIDAndLocalBasePath:
            reader.seekset(start + volume_id_offset)
            self.volume_id = VolumeID(reader)
            if has_unicode and local_base_path_offset_unicode:
                reader.seekset(start + local_base_path_offset_unicode)
                self.local_base_path = reader.read_w_string('utf-16-le')
            else:
                reader.seekset(start + local_base_path_offset)
                raw = reader.read_c_string()
                try:
                    self.local_base_path = codecs.decode(raw, 'cp1252')
                except Exception:
                    self.local_base_path = bytes(raw).hex()
        if self.flags.CommonNetworkRelativeLinkAndPathSuffix:
            reader.seekset(start + cnrl_offset)
            self.common_network_relative_link = CommonNetworkRelativeLink(reader)
        if has_unicode and common_path_suffix_offset_unicode:
            reader.seekset(start + common_path_suffix_offset_unicode)
            self.common_path_suffix = reader.read_w_string('utf-16-le')
        elif common_path_suffix_offset:
            reader.seekset(start + common_path_suffix_offset)
            raw = reader.read_c_string()
            suffix = codecs.decode(raw, 'cp1252')
            self.common_path_suffix = suffix if suffix else None
        reader.seekset(start + size)

    def __json__(self) -> dict:
        result: dict = {}
        result['flags'] = struct_to_json(self.flags)
        if self.volume_id is not None:
            result['volume_id'] = self.volume_id.__json__()
        if self.local_base_path is not None:
            result['local_base_path'] = self.local_base_path
        if self.common_network_relative_link is not None:
            result['common_network_relative_link'] = (
                self.common_network_relative_link.__json__()
            )
        if self.common_path_suffix:
            result['common_path_suffix'] = self.common_path_suffix
        return result
