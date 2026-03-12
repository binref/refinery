from __future__ import annotations

import codecs
from dataclasses import dataclass, field

from refinery.lib.lnk.idlist import LinkTargetIDList
from refinery.lib.structures import Struct, StructReader, struct_to_json

_SIG_ENVIRONMENT_VARIABLE = 0xA0000001
_SIG_CONSOLE = 0xA0000002
_SIG_TRACKER = 0xA0000003
_SIG_CONSOLE_FE = 0xA0000004
_SIG_SPECIAL_FOLDER = 0xA0000005
_SIG_DARWIN = 0xA0000006
_SIG_ICON_ENVIRONMENT = 0xA0000007
_SIG_SHIM = 0xA0000008
_SIG_PROPERTY_STORE = 0xA0000009
_SIG_KNOWN_FOLDER = 0xA000000B
_SIG_VISTA_IDLIST = 0xA000000C

_BLOCK_NAMES = {
    _SIG_ENVIRONMENT_VARIABLE : 'environment_variable',
    _SIG_CONSOLE              : 'console',
    _SIG_TRACKER              : 'tracker',
    _SIG_CONSOLE_FE           : 'console_fe',
    _SIG_SPECIAL_FOLDER       : 'special_folder',
    _SIG_DARWIN               : 'darwin',
    _SIG_ICON_ENVIRONMENT     : 'icon_environment',
    _SIG_SHIM                 : 'shim',
    _SIG_PROPERTY_STORE       : 'property_store',
    _SIG_KNOWN_FOLDER         : 'known_folder',
    _SIG_VISTA_IDLIST         : 'vista_idlist',
}


class EnvironmentVariableDataBlock(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview]):
        raw_ansi = reader.read_bytes(260)
        raw_unicode = reader.read_bytes(520)
        self.target_unicode = codecs.decode(
            raw_unicode.split(b'\0\0')[0].rstrip(b'\0'), 'utf-16-le'
        ) or None
        self.target_ansi = codecs.decode(
            raw_ansi.split(b'\0')[0], 'cp1252'
        ) or None

    def __json__(self) -> dict:
        result: dict = {'type': 'environment_variable'}
        if self.target_unicode:
            result['target'] = self.target_unicode
        elif self.target_ansi:
            result['target'] = self.target_ansi
        return result


class ConsoleDataBlock(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview]):
        self.fill_attributes = reader.u16()
        self.popup_fill_attributes = reader.u16()
        self.screen_buffer_size_x = reader.u16()
        self.screen_buffer_size_y = reader.u16()
        self.window_size_x = reader.u16()
        self.window_size_y = reader.u16()
        self.window_origin_x = reader.u16()
        self.window_origin_y = reader.u16()
        reader.skip(8)
        self.font_size = reader.u32()
        self.font_family = reader.u32()
        self.font_weight = reader.u32()
        raw_face = reader.read_bytes(64)
        self.face_name = codecs.decode(
            raw_face.split(b'\0\0')[0].rstrip(b'\0'), 'utf-16-le'
        )
        self.cursor_size = reader.u32()
        self.full_screen = reader.u32()
        self.quick_edit = reader.u32()
        self.insert_mode = reader.u32()
        self.auto_position = reader.u32()
        self.history_buffer_size = reader.u32()
        self.number_of_history_buffers = reader.u32()
        self.history_no_dup = reader.u32()
        self.color_table = [reader.u32() for _ in range(16)]


class TrackerDataBlock(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview]):
        reader.skip(8)
        raw_machine = reader.read_bytes(16)
        self.machine_id = codecs.decode(
            raw_machine.split(b'\0')[0], 'ascii'
        )
        self.droid_volume = str(reader.read_guid())
        self.droid_file = str(reader.read_guid())
        self.droid_birth_volume = str(reader.read_guid())
        self.droid_birth_file = str(reader.read_guid())


class ConsoleFEDataBlock(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview]):
        self.code_page = reader.u32()


class SpecialFolderDataBlock(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview]):
        self.special_folder_id = reader.u32()
        self.offset = reader.u32()


class DarwinDataBlock(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview]):
        raw_ansi = reader.read_bytes(260)
        raw_unicode = reader.read_bytes(520)
        self.darwin_data_unicode = codecs.decode(
            raw_unicode.split(b'\0\0')[0].rstrip(b'\0'), 'utf-16-le'
        ) or None
        self.darwin_data_ansi = codecs.decode(
            raw_ansi.split(b'\0')[0], 'cp1252'
        ) or None

    def __json__(self) -> dict:
        result: dict = {'type': 'darwin'}
        data = self.darwin_data_unicode or self.darwin_data_ansi
        if data:
            result['darwin_data'] = data
        return result


class IconEnvironmentDataBlock(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview]):
        raw_ansi = reader.read_bytes(260)
        raw_unicode = reader.read_bytes(520)
        self.target_unicode = codecs.decode(
            raw_unicode.split(b'\0\0')[0].rstrip(b'\0'), 'utf-16-le'
        ) or None
        self.target_ansi = codecs.decode(
            raw_ansi.split(b'\0')[0], 'cp1252'
        ) or None

    def __json__(self) -> dict:
        result: dict = {'type': 'icon_environment'}
        if self.target_unicode:
            result['target'] = self.target_unicode
        elif self.target_ansi:
            result['target'] = self.target_ansi
        return result


class ShimDataBlock(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview], block_data_size: int):
        raw = reader.read_bytes(block_data_size)
        self.layer_name = codecs.decode(
            raw.rstrip(b'\0').rstrip(b'\0'), 'utf-16-le'
        )


class PropertyStoreDataBlock(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview], block_data_size: int):
        self.raw = reader.read_bytes(block_data_size)

    def __json__(self) -> dict:
        return {'type': 'property_store', 'raw': self.raw.hex()}


class KnownFolderDataBlock(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview]):
        self.known_folder_id = str(reader.read_guid())
        self.offset = reader.u32()


class VistaAndAboveIDListDataBlock(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview], block_data_size: int):
        end = reader.tell() + block_data_size
        self.id_list = LinkTargetIDList(reader)
        reader.seekset(end)


@dataclass
class ExtraDataBlock:
    signature: int
    name: str
    data: Struct | None = None

    def __json__(self) -> dict:
        if self.data is not None:
            return self.data.__json__()
        return {'type': self.name, 'signature': F'0x{self.signature:08X}'}


@dataclass
class ExtraData:
    blocks: list[ExtraDataBlock] = field(default_factory=list)

    def __json__(self) -> list:
        return [struct_to_json(b.__json__()) for b in self.blocks]

    @classmethod
    def parse(cls, reader: StructReader[memoryview]) -> ExtraData:
        result = cls()
        while reader.remaining_bytes >= 4:
            block_size = reader.u32()
            if block_size < 4:
                break
            if reader.remaining_bytes < 4:
                break
            signature = reader.u32()
            data_size = block_size - 8
            name = _BLOCK_NAMES.get(signature, F'unknown_0x{signature:08X}')
            block_start = reader.tell()
            parsed: Struct | None = None
            try:
                if signature == _SIG_ENVIRONMENT_VARIABLE:
                    parsed = EnvironmentVariableDataBlock(reader)
                elif signature == _SIG_CONSOLE:
                    parsed = ConsoleDataBlock(reader)
                elif signature == _SIG_TRACKER:
                    parsed = TrackerDataBlock(reader)
                elif signature == _SIG_CONSOLE_FE:
                    parsed = ConsoleFEDataBlock(reader)
                elif signature == _SIG_SPECIAL_FOLDER:
                    parsed = SpecialFolderDataBlock(reader)
                elif signature == _SIG_DARWIN:
                    parsed = DarwinDataBlock(reader)
                elif signature == _SIG_ICON_ENVIRONMENT:
                    parsed = IconEnvironmentDataBlock(reader)
                elif signature == _SIG_SHIM:
                    parsed = ShimDataBlock(reader, data_size)
                elif signature == _SIG_PROPERTY_STORE:
                    parsed = PropertyStoreDataBlock(reader, data_size)
                elif signature == _SIG_KNOWN_FOLDER:
                    parsed = KnownFolderDataBlock(reader)
                elif signature == _SIG_VISTA_IDLIST:
                    parsed = VistaAndAboveIDListDataBlock(reader, data_size)
            except Exception:
                pass
            reader.seekset(block_start + data_size)
            result.blocks.append(ExtraDataBlock(
                signature=signature, name=name, data=parsed))
        return result
