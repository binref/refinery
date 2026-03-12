from __future__ import annotations

import codecs

from refinery.lib.structures import Struct, StructReader, struct_to_json


class ItemID:
    def __init__(self, data: memoryview):
        self.data = bytes(data)

    def __json__(self) -> dict:
        reader = StructReader(memoryview(self.data))
        if len(self.data) < 1:
            return {'raw': self.data.hex()}
        type_id = self.data[0]
        if type_id == 0x1F:
            return self._parse_root_folder(reader)
        if 0x20 <= type_id <= 0x2F:
            return self._parse_volume(reader)
        if 0x30 <= type_id <= 0x3F:
            return self._parse_file_entry(reader, type_id)
        if 0x40 <= type_id <= 0x4F:
            return self._parse_network_location(reader)
        if type_id == 0x61:
            return self._parse_uri(reader)
        return {'type': F'0x{type_id:02X}', 'raw': self.data.hex()}

    @staticmethod
    def _parse_root_folder(reader: StructReader[memoryview]) -> dict:
        result: dict = {'type': 'root_folder'}
        reader.skip(1)
        sort_index = reader.u8()
        result['sort_index'] = sort_index
        if reader.remaining_bytes >= 16:
            result['guid'] = str(reader.read_guid())
        return result

    @staticmethod
    def _parse_volume(reader: StructReader[memoryview]) -> dict:
        result: dict = {'type': 'volume'}
        reader.skip(1)
        remaining = reader.read()
        name = bytes(remaining).rstrip(b'\0')
        try:
            result['name'] = codecs.decode(name, 'utf-8')
        except Exception:
            result['name'] = name.hex()
        return result

    @staticmethod
    def _parse_file_entry(
        reader: StructReader[memoryview],
        type_id: int,
    ) -> dict:
        result: dict = {'type': 'file_entry'}
        is_directory = bool(type_id & 0x01)
        is_unicode = bool(type_id & 0x04)
        result['is_directory'] = is_directory
        reader.skip(1)
        if reader.remaining_bytes < 4:
            result['raw'] = bytes(reader.read()).hex()
            return result
        result['file_size'] = reader.u32()
        if reader.remaining_bytes >= 4:
            reader.skip(4)
        if reader.remaining_bytes >= 2:
            result['file_attributes'] = reader.u16()
        primary_name_data = reader.read_c_string()
        try:
            primary_name = codecs.decode(primary_name_data, 'utf-8')
        except Exception:
            try:
                primary_name = codecs.decode(primary_name_data, 'cp1252')
            except Exception:
                primary_name = bytes(primary_name_data).hex()
        result['primary_name'] = primary_name
        if is_unicode and reader.remaining_bytes > 4:
            try:
                if reader.remaining_bytes >= 2:
                    reader.byte_align(2)
                secondary = reader.read_w_string('utf-16-le')
                if secondary:
                    result['unicode_name'] = secondary
            except Exception:
                pass
        return result

    @staticmethod
    def _parse_network_location(reader: StructReader[memoryview]) -> dict:
        result: dict = {'type': 'network_location'}
        reader.skip(1)
        if reader.remaining_bytes >= 1:
            reader.skip(1)
        location_data = reader.read_c_string()
        try:
            result['location'] = codecs.decode(location_data, 'utf-8')
        except Exception:
            result['location'] = bytes(location_data).hex()
        if reader.remaining_bytes > 2:
            desc = reader.read_c_string()
            try:
                result['description'] = codecs.decode(desc, 'utf-8')
            except Exception:
                pass
        if reader.remaining_bytes > 2:
            comment = reader.read_c_string()
            try:
                result['comment'] = codecs.decode(comment, 'utf-8')
            except Exception:
                pass
        return result

    @staticmethod
    def _parse_uri(reader: StructReader[memoryview]) -> dict:
        result: dict = {'type': 'uri'}
        reader.skip(1)
        flags = reader.u8() if reader.remaining_bytes >= 1 else 0
        is_unicode = bool(flags & 0x80)
        if reader.remaining_bytes >= 4:
            reader.skip(4)
        remaining = bytes(reader.read())
        if is_unicode:
            try:
                result['uri'] = codecs.decode(
                    remaining, 'utf-16-le').rstrip('\0')
                return result
            except Exception:
                pass
        remaining = remaining.rstrip(b'\0')
        try:
            result['uri'] = codecs.decode(remaining, 'utf-8')
        except Exception:
            result['uri'] = remaining.hex()
        return result


class LinkTargetIDList(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview]):
        id_list_size = reader.u16()
        end_position = reader.tell() + id_list_size
        self.items: list[ItemID] = []
        while reader.tell() < end_position:
            item_size = reader.u16()
            if item_size == 0:
                break
            if item_size < 2:
                break
            item_data = reader.read(item_size - 2)
            self.items.append(ItemID(item_data))

    @property
    def path(self) -> str:
        segments: list[str] = []
        for item in self.items:
            info = item.__json__()
            item_type = info.get('type', '')
            if item_type == 'root_folder':
                continue
            elif item_type == 'volume':
                segments.append(info.get('name', ''))
            elif item_type == 'file_entry':
                segments.append(
                    info.get('unicode_name') or info.get('primary_name', ''))
            elif item_type == 'network_location':
                segments.append(info.get('location', ''))
            elif item_type == 'uri':
                return info.get('uri', '')
            else:
                segments.append(info.get('raw', ''))
        return '\\'.join(segments)

    def __json__(self) -> list:
        return [struct_to_json(item.__json__()) for item in self.items]
