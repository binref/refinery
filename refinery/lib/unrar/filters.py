"""
RAR5 data filters (decompression post-processing) and
RAR3 standard filter identification and execution.
"""
from __future__ import annotations

import enum
import struct

from dataclasses import dataclass


class FilterType(enum.IntEnum):
    FILTER_DELTA = 0
    FILTER_E8 = 1
    FILTER_E8E9 = 2
    FILTER_ARM = 3
    FILTER_AUDIO = 4
    FILTER_RGB = 5
    FILTER_ITANIUM = 6
    FILTER_PPM = 7
    FILTER_NONE = 8


@dataclass
class UnpackFilter:
    """
    A pending filter to be applied during decompression.
    """
    type: int = FilterType.FILTER_NONE
    block_start: int = 0
    block_length: int = 0
    channels: int = 0
    next_window: bool = False


def apply_filter(
    data: bytearray,
    filter_type: int,
    channels: int = 0,
    file_offset: int = 0,
) -> bytearray:
    """
    Apply a RAR5 filter to decompressed data.
    """
    if filter_type in (FilterType.FILTER_E8, FilterType.FILTER_E8E9):
        return _filter_e8(data, filter_type == FilterType.FILTER_E8E9, file_offset)
    if filter_type == FilterType.FILTER_ARM:
        return _filter_arm(data, file_offset)
    if filter_type == FilterType.FILTER_DELTA:
        return _filter_delta(data, channels)
    return data


def _filter_e8(data: bytearray, include_e9: bool, file_offset: int) -> bytearray:
    """
    x86 E8 (and optionally E9) call/jump address conversion filter: Converts relative call
    addresses to absolute addresses.
    """
    file_size = 0x1000000
    cur_pos = 0
    data_size = len(data)

    while cur_pos + 4 < data_size:
        b = data[cur_pos]
        cur_pos += 1
        if b == 0xE8 or (include_e9 and b == 0xE9):
            offset = (cur_pos + file_offset) % file_size
            addr = struct.unpack_from('<I', data, cur_pos)[0]
            if addr & 0x80000000:
                if (addr + offset) & 0x80000000 == 0:
                    struct.pack_into('<I', data, cur_pos, (addr + file_size) & 0xFFFFFFFF)
            else:
                if (addr - file_size) & 0x80000000:
                    struct.pack_into('<I', data, cur_pos, (addr - offset) & 0xFFFFFFFF)
            cur_pos += 4
    return data


def _filter_arm(data: bytearray, file_offset: int) -> bytearray:
    """
    ARM BL branch address conversion filter.
    """
    data_size = len(data)
    for cur_pos in range(0, data_size - 3, 4):
        if data[cur_pos + 3] == 0xEB:  # BL with Always condition
            offset = data[cur_pos] + data[cur_pos + 1] * 0x100 + data[cur_pos + 2] * 0x10000
            offset -= (file_offset + cur_pos) // 4
            data[cur_pos] = offset & 0xFF
            data[cur_pos + 1] = (offset >> 8) & 0xFF
            data[cur_pos + 2] = (offset >> 16) & 0xFF
    return data


def _filter_delta(data: bytearray, channels: int) -> bytearray:
    """
    Delta filter: channels bytes are grouped, then delta-decoded.
    """
    data_size = len(data)
    if channels < 1:
        return data
    dst = bytearray(data_size)
    src_pos = 0
    for cur_channel in range(channels):
        prev_byte = 0
        dest_pos = cur_channel
        while dest_pos < data_size:
            prev_byte = (prev_byte - data[src_pos]) & 0xFF
            dst[dest_pos] = prev_byte
            src_pos += 1
            dest_pos += channels
    return dst


class V3FilterType(enum.IntEnum):
    VMSF_NONE = 0
    VMSF_E8 = 1
    VMSF_E8E9 = 2
    VMSF_ITANIUM = 3
    VMSF_RGB = 4
    VMSF_AUDIO = 5
    VMSF_DELTA = 6


# RAR3 standard filter CRC32 fingerprints for identification.
# Instead of running the full VM, we identify standard filters by their
# bytecode CRC32 and execute native implementations.
_V3_FILTER_CRC = {
    0xAD576887: V3FilterType.VMSF_E8,
    0x3CD7E57E: V3FilterType.VMSF_E8E9,
    0x3769893F: V3FilterType.VMSF_ITANIUM,
    0x0E06077D: V3FilterType.VMSF_DELTA,
    0x1C2C5DC8: V3FilterType.VMSF_RGB,
    0xBC85E701: V3FilterType.VMSF_AUDIO,
}


def identify_v3_filter(code_crc: int):
    """
    Identify a RAR3 VM filter by its bytecode CRC32.
    """
    return _V3_FILTER_CRC.get(code_crc, V3FilterType.VMSF_NONE)


def execute_v3_filter(
    filter_type: int,
    data: bytearray,
    block_length: int,
    initial_register_values: list[int] | None = None
) -> bytearray:
    """
    Execute a RAR3 standard filter.
    """
    ir = initial_register_values
    if filter_type == V3FilterType.VMSF_E8:
        return _v3_filter_e8(data, block_length, False, ir)
    elif filter_type == V3FilterType.VMSF_E8E9:
        return _v3_filter_e8(data, block_length, True, ir)
    elif filter_type == V3FilterType.VMSF_ITANIUM:
        return _v3_filter_itanium(data, block_length, ir)
    elif filter_type == V3FilterType.VMSF_DELTA:
        return _v3_filter_delta(data, block_length, ir)
    elif filter_type == V3FilterType.VMSF_RGB:
        return _v3_filter_rgb(data, block_length, ir)
    elif filter_type == V3FilterType.VMSF_AUDIO:
        return _v3_filter_audio(data, block_length, ir)
    raise NotImplementedError(F'Non-standard RAR3 VM filter type: {filter_type}')


def _v3_filter_e8(
    data: bytearray,
    data_size: int,
    include_e9: bool,
    initial_register_values: list[int] | None = None
) -> bytearray:
    """
    RAR3 E8/E8E9 filter (same logic as RAR5 version).
    """
    file_size = 0x1000000
    file_offset = initial_register_values[6] if initial_register_values else 0
    cur_pos = 0
    while cur_pos + 4 < data_size:
        b = data[cur_pos]
        cur_pos += 1
        if b == 0xE8 or (include_e9 and b == 0xE9):
            offset = (cur_pos + file_offset) & 0xFFFFFFFF
            addr = struct.unpack_from('<I', data, cur_pos)[0]
            if addr & 0x80000000:
                if (addr + offset) & 0x80000000 == 0:
                    struct.pack_into('<I', data, cur_pos, (addr + file_size) & 0xFFFFFFFF)
            else:
                if (addr - file_size) & 0x80000000:
                    struct.pack_into('<I', data, cur_pos, (addr - offset) & 0xFFFFFFFF)
            cur_pos += 4
    return data


def _v3_filter_itanium(data: bytearray, data_size: int, init_r: list[int] | None) -> bytearray:
    """
    RAR3 Itanium filter: IA-64 branch address conversion.
    """
    file_offset = init_r[6] if init_r else 0
    aligned_size = data_size & ~0xF
    byte_masks = (4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4, 0, 0)

    for i in range(0, aligned_size, 16):
        mask_index = data[i] & 0x1F
        if mask_index >= 16:
            continue
        cmd_mask = byte_masks[mask_index]
        if cmd_mask == 0:
            continue
        for j in range(3):
            if not (cmd_mask & (1 << j)):
                continue
            start_pos = i + 5 * j + 5
            if start_pos + 4 > data_size:
                break
            bit_pos = (start_pos & 0xF) * 8
            # Extract bits from the 128-bit bundle
            idx = start_pos & ~0xF
            if idx + 16 > len(data):
                break
            val = int.from_bytes(data[idx:idx + 16], 'little')
            op_code = (val >> bit_pos) & 0xFFFFFFFFFF  # 41-bit instruction
            if ((op_code >> 37) & 0xF) == 5:
                addr = (((op_code >> 13) & 0xFFFFF) | ((op_code >> 36) & 1) << 20) << 4
                addr -= file_offset + i
                addr = (addr >> 4) & 0x1FFFFF
                raw = op_code & ~(0x1FFFFF << 13)
                raw |= ((addr & 0xFFFFF) << 13) | ((addr >> 20) << 36)
                # Write back
                mask = ((1 << 41) - 1) << bit_pos
                val = (val & ~mask) | ((raw & ((1 << 41) - 1)) << bit_pos)
                data[idx:idx + 16] = val.to_bytes(16, 'little')
    return data


def _v3_filter_delta(data: bytearray, data_size: int, init_r: list[int] | None) -> bytearray:
    """
    RAR3 delta filter.
    """
    channels = init_r[0] if init_r else 1
    return _filter_delta(data[:data_size], channels)


def _v3_filter_rgb(data: bytearray, data_size: int, init_r: list[int] | None) -> bytearray:
    """
    RAR3 RGB delta filter.
    """
    width = (init_r[0] - 3) if init_r else 3
    pos_r = init_r[1] if init_r else 0
    channels = 3
    dst = bytearray(data_size)
    src_pos = 0
    for cur_channel in range(channels):
        prev_byte = 0
        for i in range(cur_channel, data_size, channels):
            predicted = prev_byte
            upper_pos = i - width
            if upper_pos >= channels:
                upper_left = dst[upper_pos - channels] if upper_pos >= channels else 0
                upper = dst[upper_pos]
                predicted = prev_byte + upper - upper_left
                pa = abs(predicted - prev_byte)
                pb = abs(predicted - upper)
                pc = abs(predicted - upper_left)
                if pa <= pb and pa <= pc:
                    predicted = prev_byte
                elif pb <= pc:
                    predicted = upper
                else:
                    predicted = upper_left
            if src_pos < data_size:
                prev_byte = (predicted - data[src_pos]) & 0xFF
                dst[i] = prev_byte
                src_pos += 1

    # Green-channel post-processing: add green to R and B
    if data_size >= 3:
        border = data_size - 2
        i = pos_r
        while i < border:
            g = dst[i + 1]
            dst[i + 0] = (dst[i + 0] + g) & 0xFF
            dst[i + 2] = (dst[i + 2] + g) & 0xFF
            i += 3

    return dst


def _v3_filter_audio(data: bytearray, data_size: int, init_r: list[int] | None) -> bytearray:
    """
    RAR3 audio delta filter with adaptive prediction.
    """
    channels = init_r[0] if init_r else 1
    if channels == 0:
        channels = 1
    dst = bytearray(data_size)
    src_pos = 0
    _U32 = 0xFFFFFFFF

    def _s32(v):
        v &= _U32
        return v - 0x100000000 if v >= 0x80000000 else v

    for cur_channel in range(channels):
        prev_byte = 0    # uint
        prev_delta = 0   # uint
        d1 = 0           # int
        d2 = 0           # int
        k1 = 0           # int
        k2 = 0           # int
        k3 = 0           # int
        dif = [0] * 7    # uint[7]
        byte_count = 0

        i = cur_channel
        while i < data_size:
            if src_pos >= data_size:
                break
            d3 = d2
            # C++: D2=PrevDelta-D1 (uint - int -> uint, stored in int)
            d2 = _s32(prev_delta - d1)
            d1 = _s32(prev_delta)

            # C++: uint Predicted=8*PrevByte+K1*D1+K2*D2+K3*D3;
            predicted = (8 * prev_byte + k1 * d1 + k2 * d2 + k3 * d3) & _U32
            # C++: Predicted=(Predicted>>3) & 0xff;  (unsigned right shift)
            predicted = (predicted >> 3) & 0xFF

            cur_byte = data[src_pos]
            src_pos += 1

            # C++: Predicted-=CurByte;  (uint -= uint, wraps)
            predicted = (predicted - cur_byte) & 0xFF
            dst[i] = predicted

            # C++: PrevDelta=(signed char)(Predicted-PrevByte);
            # (signed char) truncates to 8-bit signed, then assigned to uint
            delta = (predicted - prev_byte) & 0xFF
            if delta >= 128:
                prev_delta = (delta - 256) & _U32
            else:
                prev_delta = delta
            prev_byte = predicted

            # C++: int D=(signed char)CurByte; D=(uint)D<<3;
            d = cur_byte if cur_byte < 128 else cur_byte - 256
            d = _s32(d << 3)

            dif[0] = (dif[0] + abs(d)) & _U32
            dif[1] = (dif[1] + abs(d - d1)) & _U32
            dif[2] = (dif[2] + abs(d + d1)) & _U32
            dif[3] = (dif[3] + abs(d - d2)) & _U32
            dif[4] = (dif[4] + abs(d + d2)) & _U32
            dif[5] = (dif[5] + abs(d - d3)) & _U32
            dif[6] = (dif[6] + abs(d + d3)) & _U32

            if (byte_count & 0x1F) == 0:
                min_dif = dif[0]
                num_min_dif = 0
                dif[0] = 0
                for j in range(1, 7):
                    if dif[j] < min_dif:
                        min_dif = dif[j]
                        num_min_dif = j
                    dif[j] = 0
                if num_min_dif == 1:
                    if k1 >= -16:
                        k1 -= 1
                elif num_min_dif == 2:
                    if k1 < 16:
                        k1 += 1
                elif num_min_dif == 3:
                    if k2 >= -16:
                        k2 -= 1
                elif num_min_dif == 4:
                    if k2 < 16:
                        k2 += 1
                elif num_min_dif == 5:
                    if k3 >= -16:
                        k3 -= 1
                elif num_min_dif == 6:
                    if k3 < 16:
                        k3 += 1

            byte_count += 1
            i += channels
    return dst
