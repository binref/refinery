"""
Physical sector layouts of optical disc images. A raw CD image stores each sector with its sync
pattern, header, and error correction data, whereas the file system parsers of `refinery.lib.iso`
expect the 2048-byte user data of all sectors in sequence.
"""
from __future__ import annotations

import enum

from typing import NamedTuple

from refinery.lib.types import buf

USER_DATA_SIZE = 2048
RAW_SECTOR_SIZES = (2352, 2448)
SYNC_PATTERN = B'\x00' + B'\xFF' * 10 + B'\x00'
HEADER_SIZE = 16
XA_SUBHEADER_SIZE = 8
FIRST_VOLUME_DESCRIPTOR_SECTOR = 16


class SectorMode(enum.IntEnum):
    """
    The mode byte in the header of a raw CD sector.
    """
    MODE1 = 1
    MODE2 = 2


class SectorLayout(NamedTuple):
    """
    Size of the physical sectors of a disc image and the offset of the 2048 bytes of user data
    within each of them.
    """
    sector_size: int
    data_offset: int

    @classmethod
    def detect(cls, data: buf) -> SectorLayout:
        """
        Detect a raw sector layout from the header of the sector that holds the first volume
        descriptor; both ISO 9660 and UDF place it at sector 16. Mode 2 sectors are assumed to be
        CD-ROM XA Form 1 sectors, which carry an 8-byte subheader before the user data. Returns
        `COOKED` when no raw sector header is found.
        """
        view = memoryview(data)
        for sector_size in RAW_SECTOR_SIZES:
            header = view[FIRST_VOLUME_DESCRIPTOR_SECTOR * sector_size:][:HEADER_SIZE]
            if len(header) < HEADER_SIZE or header[:len(SYNC_PATTERN)] != SYNC_PATTERN:
                continue
            mode = header[-1]
            if mode == SectorMode.MODE1:
                return cls(sector_size, HEADER_SIZE)
            if mode == SectorMode.MODE2:
                return cls(sector_size, HEADER_SIZE + XA_SUBHEADER_SIZE)
        return COOKED

    @property
    def raw(self) -> bool:
        return self != COOKED

    def position(self, sector: int) -> int:
        """
        The offset of the user data of the given logical sector in the disc image.
        """
        return sector * self.sector_size + self.data_offset

    def user_data(self, data: buf) -> bytearray:
        """
        Concatenate the user data of all sectors; a truncated last sector contributes the part of
        its user data that is present.
        """
        view = memoryview(data)
        starts = range(self.data_offset, len(view), self.sector_size)
        return bytearray().join(view[k:k + USER_DATA_SIZE] for k in starts)


COOKED = SectorLayout(USER_DATA_SIZE, 0)
