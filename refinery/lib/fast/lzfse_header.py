"""
Reads the block headers of an LZFSE stream for both LZFSE decoders in `refinery.lib.fast.lzfse` and
checks that each block lies within the input and that its fields are in range.
"""
from __future__ import annotations

import enum
import struct

from typing import NamedTuple

LITERALS_PER_BLOCK = 40000
MATCHES_PER_BLOCK = 10000

_LITERAL_STATES = 1024
_L_STATES = 64
_M_STATES = 64
_D_STATES = 256

_LONGEST_LZFSE_MATCH = 2359
_LONGEST_LZVN_MATCH = 271

_V2_FIXED_SIZE = 32

_RAW_FIELDS = struct.Struct('<I')
_LZVN_FIELDS = struct.Struct('<II')
_V1_FIELDS = struct.Struct('<6Ii4HiHHH360H2x')
_V2_FIELDS = struct.Struct('<IQQQ')


class BlockKind(enum.IntEnum):
    END = 0x24787662
    RAW = 0x2D787662
    LZFSE_V1 = 0x31787662
    LZFSE_V2 = 0x32787662
    LZVN = 0x6E787662


class BlockHeader(NamedTuple):
    kind: BlockKind
    end: int
    raw_size: int = 0
    payload: int = 0
    freq_table: int = 0
    literal_payload_size: int = 0
    lmd_payload_size: int = 0
    n_literals: int = 0
    n_matches: int = 0
    literal_bits: int = 0
    literal_states: tuple[int, ...] = ()
    lmd_bits: int = 0
    l_state: int = 0
    m_state: int = 0
    d_state: int = 0
    freqs: tuple[int, ...] = ()


def read_block_header(data: memoryview, pos: int) -> BlockHeader:
    """
    Read the header of the block at offset `pos`. The compressed frequency table of an LZFSE V2
    block is not decoded; it begins at `BlockHeader.freq_table` and ends at `BlockHeader.payload`.
    """
    if pos + 4 > len(data):
        raise ValueError('the input ends before the end-of-stream block')
    magic = int.from_bytes(data[pos:pos + 4], 'little')
    try:
        kind = BlockKind(magic)
    except ValueError:
        raise ValueError(F'unknown LZFSE block magic: 0x{magic:08X}') from None
    body = pos + 4
    if kind is BlockKind.END:
        return BlockHeader(kind, body)
    if kind is BlockKind.RAW:
        raw_size, = _fields(_RAW_FIELDS, data, pos)
        payload = body + _RAW_FIELDS.size
        header = BlockHeader(kind, payload + raw_size, raw_size, payload)
    elif kind is BlockKind.LZVN:
        raw_size, size = _fields(_LZVN_FIELDS, data, pos)
        payload = body + _LZVN_FIELDS.size
        header = BlockHeader(kind, payload + size, raw_size, payload)
    elif kind is BlockKind.LZFSE_V1:
        fields = _fields(_V1_FIELDS, data, pos)
        raw_size, size, n_literals, n_matches, literal_payload_size, lmd_payload_size = fields[:6]
        if literal_payload_size + lmd_payload_size > size:
            raise ValueError(F'the payloads of the LZFSE block at offset {pos} exceed the block')
        payload = body + _V1_FIELDS.size
        header = BlockHeader(
            kind,
            end=payload + size,
            raw_size=raw_size,
            payload=payload,
            literal_payload_size=literal_payload_size,
            lmd_payload_size=lmd_payload_size,
            n_literals=n_literals,
            n_matches=n_matches,
            literal_bits=fields[6],
            literal_states=fields[7:11],
            lmd_bits=fields[11],
            l_state=fields[12],
            m_state=fields[13],
            d_state=fields[14],
            freqs=fields[15:],
        )
    else:
        raw_size, v0, v1, v2 = _fields(_V2_FIELDS, data, pos)
        header_size = v2 & 0xFFFFFFFF
        if header_size <= _V2_FIXED_SIZE:
            raise ValueError(F'the LZFSE block at offset {pos} has no frequency table')
        payload = pos + header_size
        literal_payload_size = (v0 >> 20) & 0xFFFFF
        lmd_payload_size = (v1 >> 40) & 0xFFFFF
        header = BlockHeader(
            kind,
            end=payload + literal_payload_size + lmd_payload_size,
            raw_size=raw_size,
            payload=payload,
            freq_table=pos + _V2_FIXED_SIZE,
            literal_payload_size=literal_payload_size,
            lmd_payload_size=lmd_payload_size,
            n_literals=v0 & 0xFFFFF,
            n_matches=(v0 >> 40) & 0xFFFFF,
            literal_bits=((v0 >> 60) & 7) - 7,
            literal_states=(v1 & 0x3FF, (v1 >> 10) & 0x3FF, (v1 >> 20) & 0x3FF, (v1 >> 30) & 0x3FF),
            lmd_bits=((v1 >> 60) & 7) - 7,
            l_state=(v2 >> 32) & 0x3FF,
            m_state=(v2 >> 42) & 0x3FF,
            d_state=(v2 >> 52) & 0x3FF,
        )
    if header.end > len(data):
        raise ValueError(F'the LZFSE block at offset {pos} ends after the end of the input')
    if kind in (BlockKind.LZFSE_V1, BlockKind.LZFSE_V2) and not _lzfse_fields_in_range(header):
        raise ValueError(F'the LZFSE block at offset {pos} has an invalid header')
    if header.raw_size > _most_output(header):
        raise ValueError(F'the LZFSE block at offset {pos} claims more output than it can produce')
    return header


def _most_output(header: BlockHeader) -> int:
    """
    The largest output that the payload of the block can decode to. No LZVN instruction produces
    more output per payload byte than a match of the longest length, which takes two bytes.
    """
    if header.kind is BlockKind.RAW:
        return header.raw_size
    if header.kind is BlockKind.LZVN:
        return (header.end - header.payload + 1) // 2 * _LONGEST_LZVN_MATCH
    return header.n_literals + header.n_matches * _LONGEST_LZFSE_MATCH


def _lzfse_fields_in_range(header: BlockHeader) -> bool:
    return (
        header.n_literals <= LITERALS_PER_BLOCK
        and header.n_literals % 4 == 0
        and header.n_matches <= MATCHES_PER_BLOCK
        and max(header.literal_states) < _LITERAL_STATES
        and header.l_state < _L_STATES
        and header.m_state < _M_STATES
        and header.d_state < _D_STATES
        and -7 <= header.literal_bits <= 0
        and -7 <= header.lmd_bits <= 0
    )


def _fields(layout: struct.Struct, data: memoryview, pos: int) -> tuple[int, ...]:
    body = pos + 4
    if body + layout.size > len(data):
        raise ValueError(F'the header of the LZFSE block at offset {pos} is cut off')
    return layout.unpack_from(data, body)
