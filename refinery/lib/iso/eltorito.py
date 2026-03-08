"""
El Torito boot catalog parser for ISO 9660 images.
"""
from __future__ import annotations

import struct

PLATFORM_X86 = 0
PLATFORM_PPC = 1
PLATFORM_MAC = 2
PLATFORM_EFI = 0xEF

MEDIA_NO_EMULATION = 0
MEDIA_12_FLOPPY = 1
MEDIA_144_FLOPPY = 2
MEDIA_288_FLOPPY = 3
MEDIA_HARD_DISK = 4

FLOPPY_12_SECTORS = 2400
FLOPPY_144_SECTORS = 2880
FLOPPY_288_SECTORS = 5760

SECTOR_SIZE = 0x200


class BootEntry:
    __slots__ = (
        'is_bootable',
        'media_type',
        'load_segment',
        'system_type',
        'sector_count',
        'load_rba',
        'platform_id',
        'name',
    )

    def __init__(self):
        self.is_bootable: bool = False
        self.media_type: int = 0
        self.load_segment: int = 0
        self.system_type: int = 0
        self.sector_count: int = 0
        self.load_rba: int = 0
        self.platform_id: int = PLATFORM_X86
        self.name: str = ''

    @property
    def image_size(self) -> int:
        media = self.media_type & 0x0F
        if media == MEDIA_NO_EMULATION:
            return self.sector_count * SECTOR_SIZE
        elif media == MEDIA_12_FLOPPY:
            return FLOPPY_12_SECTORS * SECTOR_SIZE
        elif media == MEDIA_144_FLOPPY:
            return FLOPPY_144_SECTORS * SECTOR_SIZE
        elif media == MEDIA_288_FLOPPY:
            return FLOPPY_288_SECTORS * SECTOR_SIZE
        elif media == MEDIA_HARD_DISK:
            return self.sector_count * SECTOR_SIZE
        return self.sector_count * SECTOR_SIZE


def _platform_name(pid: int) -> str:
    names = {
        PLATFORM_X86 : 'x86',
        PLATFORM_PPC : 'PPC',
        PLATFORM_MAC : 'Mac',
        PLATFORM_EFI : 'EFI',
    }
    return names.get(pid, F'Platform{pid:02X}')


def _media_name(media: int) -> str:
    media &= 0x0F
    names = {
        MEDIA_NO_EMULATION : 'NoEmul',
        MEDIA_12_FLOPPY    : '1.2M',
        MEDIA_144_FLOPPY   : '1.44M',
        MEDIA_288_FLOPPY   : '2.88M',
        MEDIA_HARD_DISK    : 'HardDisk',
    }
    return names.get(media, F'Media{media:02X}')


def generate_boot_entry_name(entry: BootEntry, index: int) -> str:
    parts = ['[BOOT]']
    parts.append(_platform_name(entry.platform_id))
    parts.append(_media_name(entry.media_type))
    if not entry.is_bootable:
        parts.append('NotBootable')
    parts.append(F'Image{index}')
    return '-'.join(parts) + '.img'


class BootCatalog:
    __slots__ = ('entries', 'validation_platform_id')

    def __init__(self):
        self.entries: list[BootEntry] = []
        self.validation_platform_id: int = 0

    @classmethod
    def parse(cls, data: bytes) -> BootCatalog | None:
        if len(data) < 64:
            return None
        catalog = cls()
        if not catalog._parse_validation_entry(data[:32]):
            return None
        initial = catalog._parse_initial_entry(data[32:64])
        if initial:
            initial.platform_id = catalog.validation_platform_id
            catalog.entries.append(initial)
        pos = 64
        current_platform = catalog.validation_platform_id
        while pos + 32 <= len(data):
            header_id = data[pos]
            if header_id == 0x90 or header_id == 0x91:
                current_platform = data[pos + 1]
                num_entries, = struct.unpack_from('<H', data, pos + 2)
                pos += 32
                for _ in range(num_entries):
                    if pos + 32 > len(data):
                        break
                    entry = catalog._parse_section_entry(data[pos:pos + 32])
                    if entry:
                        entry.platform_id = current_platform
                        catalog.entries.append(entry)
                    pos += 32
                if header_id == 0x91:
                    break
            else:
                break
        for i, entry in enumerate(catalog.entries):
            entry.name = generate_boot_entry_name(entry, i)
        return catalog

    def _parse_validation_entry(self, data: bytes) -> bool:
        if data[0] != 0x01:
            return False
        self.validation_platform_id = data[1]
        checksum = 0
        for i in range(0, 32, 2):
            checksum += struct.unpack_from('<H', data, i)[0]
        return (checksum & 0xFFFF) == 0

    def _parse_initial_entry(self, data: bytes) -> BootEntry | None:
        entry = BootEntry()
        entry.is_bootable = (data[0] == 0x88)
        entry.media_type = data[1]
        entry.load_segment, = struct.unpack_from('<H', data, 2)
        entry.system_type = data[4]
        entry.sector_count, = struct.unpack_from('<H', data, 6)
        entry.load_rba, = struct.unpack_from('<I', data, 8)
        return entry

    def _parse_section_entry(self, data: bytes) -> BootEntry | None:
        entry = BootEntry()
        entry.is_bootable = (data[0] == 0x88)
        entry.media_type = data[1]
        entry.load_segment, = struct.unpack_from('<H', data, 2)
        entry.system_type = data[4]
        entry.sector_count, = struct.unpack_from('<H', data, 6)
        entry.load_rba, = struct.unpack_from('<I', data, 8)
        return entry
