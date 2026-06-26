"""
Implements the CRC-32C (Castagnoli) checksum, which is used by the VHDX virtual disk format to
validate its headers and region tables. The polynomial differs from the one used by `zlib.crc32`,
so a dedicated implementation is required.
"""
from __future__ import annotations

from refinery.lib.types import buf

_POLYNOMIAL = 0x82F63B78


def _make_table() -> list[int]:
    table = []
    for index in range(256):
        crc = index
        for _ in range(8):
            crc = (crc >> 1) ^ (_POLYNOMIAL & -(crc & 1) & 0xFFFFFFFF)
        table.append(crc)
    return table


_TABLE = _make_table()


def crc32c(data: buf, crc: int = 0) -> int:
    """
    Compute the CRC-32C (Castagnoli) checksum of the input `data`. An initial CRC value can be
    passed to continue a previous computation.
    """
    crc ^= 0xFFFFFFFF
    table = _TABLE
    for byte in bytes(data):
        crc = table[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF
