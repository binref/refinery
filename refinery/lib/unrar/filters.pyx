# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True
"""
RAR5 data filters (decompression post-processing) and
RAR3 standard filter identification and execution.

Cython-optimized version of filters.py.
"""
cimport cython

from cpython.bytearray cimport PyByteArray_AS_STRING
from libc.string cimport memset

import enum

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
    next_window: int = 0


def apply_filter(
    bytearray data,
    int filter_type,
    int channels=0,
    int file_offset=0,
):
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


cdef bytearray _filter_e8(bytearray data, bint include_e9, int file_offset):
    cdef unsigned char *ptr = <unsigned char *>PyByteArray_AS_STRING(data)
    cdef int data_size = len(data)
    cdef int file_size = 0x1000000
    cdef int cur_pos = 0
    cdef unsigned char b
    cdef unsigned int offset, addr, val

    while cur_pos + 4 < data_size:
        b = ptr[cur_pos]
        cur_pos += 1
        if b == 0xE8 or (include_e9 and b == 0xE9):
            offset = (cur_pos + file_offset) % file_size
            addr = (
                <unsigned int>ptr[cur_pos]
                | (<unsigned int>ptr[cur_pos + 1] << 8)
                | (<unsigned int>ptr[cur_pos + 2] << 16)
                | (<unsigned int>ptr[cur_pos + 3] << 24)
            )
            if addr & 0x80000000:
                if (addr + offset) & 0x80000000 == 0:
                    val = (addr + file_size) & 0xFFFFFFFF
                    ptr[cur_pos] = val & 0xFF
                    ptr[cur_pos + 1] = (val >> 8) & 0xFF
                    ptr[cur_pos + 2] = (val >> 16) & 0xFF
                    ptr[cur_pos + 3] = (val >> 24) & 0xFF
            else:
                if (addr - file_size) & 0x80000000:
                    val = (addr - offset) & 0xFFFFFFFF
                    ptr[cur_pos] = val & 0xFF
                    ptr[cur_pos + 1] = (val >> 8) & 0xFF
                    ptr[cur_pos + 2] = (val >> 16) & 0xFF
                    ptr[cur_pos + 3] = (val >> 24) & 0xFF
            cur_pos += 4
    return data


cdef bytearray _filter_arm(bytearray data, int file_offset):
    cdef unsigned char *ptr = <unsigned char *>PyByteArray_AS_STRING(data)
    cdef int data_size = len(data)
    cdef int cur_pos
    cdef unsigned int offset

    for cur_pos in range(0, data_size - 3, 4):
        if ptr[cur_pos + 3] == 0xEB:
            offset = (
                <unsigned int>ptr[cur_pos]
                + <unsigned int>ptr[cur_pos + 1] * 0x100
                + <unsigned int>ptr[cur_pos + 2] * 0x10000
            )
            offset -= (file_offset + cur_pos) // 4
            ptr[cur_pos] = offset & 0xFF
            ptr[cur_pos + 1] = (offset >> 8) & 0xFF
            ptr[cur_pos + 2] = (offset >> 16) & 0xFF
    return data


cdef bytearray _filter_delta(bytearray data, int channels):
    cdef int data_size = len(data)
    cdef unsigned char *src
    cdef unsigned char *dst_ptr
    cdef int src_pos, dest_pos, cur_channel
    cdef unsigned char prev_byte

    if channels < 1:
        return data
    dst = bytearray(data_size)
    src = <unsigned char *>PyByteArray_AS_STRING(data)
    dst_ptr = <unsigned char *>PyByteArray_AS_STRING(dst)
    src_pos = 0
    for cur_channel in range(channels):
        prev_byte = 0
        dest_pos = cur_channel
        while dest_pos < data_size:
            prev_byte = (prev_byte - src[src_pos]) & 0xFF
            dst_ptr[dest_pos] = prev_byte
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


_V3_FILTER_CRC = {
    0xAD576887: V3FilterType.VMSF_E8,
    0x3CD7E57E: V3FilterType.VMSF_E8E9,
    0x3769893F: V3FilterType.VMSF_ITANIUM,
    0x0E06077D: V3FilterType.VMSF_DELTA,
    0x1C2C5DC8: V3FilterType.VMSF_RGB,
    0xBC85E701: V3FilterType.VMSF_AUDIO,
}


def identify_v3_filter(code_crc):
    """
    Identify a RAR3 VM filter by its bytecode CRC32.
    """
    return _V3_FILTER_CRC.get(code_crc, V3FilterType.VMSF_NONE)


def execute_v3_filter(
    int filter_type,
    bytearray data,
    int block_length,
    list initial_register_values=None,
):
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


cdef bytearray _v3_filter_e8(
    bytearray data,
    int data_size,
    bint include_e9,
    list initial_register_values,
):
    cdef unsigned char *ptr = <unsigned char *>PyByteArray_AS_STRING(data)
    cdef int file_size = 0x1000000
    cdef int file_offset = 0
    cdef int cur_pos = 0
    cdef unsigned char b
    cdef unsigned int offset, addr, val

    if initial_register_values is not None:
        file_offset = <int>initial_register_values[6]

    while cur_pos + 4 < data_size:
        b = ptr[cur_pos]
        cur_pos += 1
        if b == 0xE8 or (include_e9 and b == 0xE9):
            offset = (cur_pos + file_offset) & 0xFFFFFFFF
            addr = (
                <unsigned int>ptr[cur_pos]
                | (<unsigned int>ptr[cur_pos + 1] << 8)
                | (<unsigned int>ptr[cur_pos + 2] << 16)
                | (<unsigned int>ptr[cur_pos + 3] << 24)
            )
            if addr & 0x80000000:
                if (addr + offset) & 0x80000000 == 0:
                    val = (addr + file_size) & 0xFFFFFFFF
                    ptr[cur_pos] = val & 0xFF
                    ptr[cur_pos + 1] = (val >> 8) & 0xFF
                    ptr[cur_pos + 2] = (val >> 16) & 0xFF
                    ptr[cur_pos + 3] = (val >> 24) & 0xFF
            else:
                if (addr - file_size) & 0x80000000:
                    val = (addr - offset) & 0xFFFFFFFF
                    ptr[cur_pos] = val & 0xFF
                    ptr[cur_pos + 1] = (val >> 8) & 0xFF
                    ptr[cur_pos + 2] = (val >> 16) & 0xFF
                    ptr[cur_pos + 3] = (val >> 24) & 0xFF
            cur_pos += 4
    return data


cdef bytearray _v3_filter_itanium(bytearray data, int data_size, list init_r):
    cdef unsigned char *ptr = <unsigned char *>PyByteArray_AS_STRING(data)
    cdef int file_offset = 0
    cdef int aligned_size
    cdef int i, j, start_pos, bit_pos, idx
    cdef unsigned int mask_index, cmd_mask
    cdef int data_len = len(data)

    if init_r is not None:
        file_offset = <int>init_r[6]
    aligned_size = data_size & ~0xF

    byte_masks = (4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4, 0, 0)

    for i in range(0, aligned_size, 16):
        mask_index = ptr[i] & 0x1F
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
            idx = start_pos & ~0xF
            if idx + 16 > data_len:
                break
            val = int.from_bytes(data[idx:idx + 16], 'little')
            op_code = (val >> bit_pos) & 0xFFFFFFFFFF
            if ((op_code >> 37) & 0xF) == 5:
                addr = (((op_code >> 13) & 0xFFFFF) | ((op_code >> 36) & 1) << 20) << 4
                addr -= file_offset + i
                addr = (addr >> 4) & 0x1FFFFF
                raw = op_code & ~(0x1FFFFF << 13)
                raw |= ((addr & 0xFFFFF) << 13) | ((addr >> 20) << 36)
                mask = ((1 << 41) - 1) << bit_pos
                val = (val & ~mask) | ((raw & ((1 << 41) - 1)) << bit_pos)
                data[idx:idx + 16] = val.to_bytes(16, 'little')
    return data


cdef bytearray _v3_filter_delta(bytearray data, int data_size, list init_r):
    cdef int channels = 1
    if init_r is not None:
        channels = <int>init_r[0]
    return _filter_delta(data[:data_size], channels)


cdef bytearray _v3_filter_rgb(bytearray data, int data_size, list init_r):
    cdef int width = 3
    cdef int pos_r = 0
    cdef int channels = 3
    cdef unsigned char *src
    cdef unsigned char *dst_ptr
    cdef int src_pos = 0
    cdef int cur_channel, i, upper_pos
    cdef int predicted, pa, pb, pc
    cdef unsigned char prev_byte, upper, upper_left, g
    cdef int border

    if init_r is not None:
        width = <int>init_r[0] - 3
        pos_r = <int>init_r[1]

    dst = bytearray(data_size)
    src = <unsigned char *>PyByteArray_AS_STRING(data)
    dst_ptr = <unsigned char *>PyByteArray_AS_STRING(dst)

    for cur_channel in range(channels):
        prev_byte = 0
        for i in range(cur_channel, data_size, channels):
            predicted = prev_byte
            upper_pos = i - width
            if upper_pos >= channels:
                upper_left = dst_ptr[upper_pos - channels] if upper_pos >= channels else 0
                upper = dst_ptr[upper_pos]
                predicted = <int>prev_byte + <int>upper - <int>upper_left
                pa = predicted - <int>prev_byte
                if pa < 0:
                    pa = -pa
                pb = predicted - <int>upper
                if pb < 0:
                    pb = -pb
                pc = predicted - <int>upper_left
                if pc < 0:
                    pc = -pc
                if pa <= pb and pa <= pc:
                    predicted = prev_byte
                elif pb <= pc:
                    predicted = upper
                else:
                    predicted = upper_left
            if src_pos < data_size:
                prev_byte = (predicted - src[src_pos]) & 0xFF
                dst_ptr[i] = prev_byte
                src_pos += 1

    if data_size >= 3:
        border = data_size - 2
        i = pos_r
        while i < border:
            g = dst_ptr[i + 1]
            dst_ptr[i + 0] = (dst_ptr[i + 0] + g) & 0xFF
            dst_ptr[i + 2] = (dst_ptr[i + 2] + g) & 0xFF
            i += 3

    return dst


cdef inline int _s32(unsigned int v):
    return <int>v


cdef bytearray _v3_filter_audio(bytearray data, int data_size, list init_r):
    cdef int channels = 1
    cdef unsigned char *src
    cdef unsigned char *dst_ptr
    cdef int src_pos = 0
    cdef unsigned int _U32 = 0xFFFFFFFF
    cdef int cur_channel, i, byte_count
    cdef unsigned int prev_byte, prev_delta
    cdef unsigned int dif[7]
    cdef int d1, d2, d3, k1, k2, k3
    cdef unsigned int predicted, cur_byte, delta
    cdef int d
    cdef unsigned int min_dif
    cdef int num_min_dif, j

    if init_r is not None:
        channels = <int>init_r[0]
    if channels == 0:
        channels = 1

    dst = bytearray(data_size)
    src = <unsigned char *>PyByteArray_AS_STRING(data)
    dst_ptr = <unsigned char *>PyByteArray_AS_STRING(dst)

    for cur_channel in range(channels):
        prev_byte = 0
        prev_delta = 0
        d1 = 0
        d2 = 0
        k1 = 0
        k2 = 0
        k3 = 0
        memset(dif, 0, 7 * sizeof(unsigned int))
        byte_count = 0

        i = cur_channel
        while i < data_size:
            if src_pos >= data_size:
                break
            d3 = d2
            d2 = _s32(prev_delta - <unsigned int>d1)
            d1 = _s32(prev_delta)

            predicted = (8 * prev_byte + <unsigned int>k1 * <unsigned int>d1
                + <unsigned int>k2 * <unsigned int>d2
                + <unsigned int>k3 * <unsigned int>d3) & _U32
            predicted = (predicted >> 3) & 0xFF

            cur_byte = src[src_pos]
            src_pos += 1

            predicted = (predicted - cur_byte) & 0xFF
            dst_ptr[i] = <unsigned char>predicted

            delta = (predicted - prev_byte) & 0xFF
            if delta >= 128:
                prev_delta = (delta - 256) & _U32
            else:
                prev_delta = delta
            prev_byte = predicted

            d = <int>cur_byte if cur_byte < 128 else <int>cur_byte - 256
            d = _s32(<unsigned int>d << 3)

            dif[0] = (dif[0] + <unsigned int>abs(d)) & _U32
            dif[1] = (dif[1] + <unsigned int>abs(d - d1)) & _U32
            dif[2] = (dif[2] + <unsigned int>abs(d + d1)) & _U32
            dif[3] = (dif[3] + <unsigned int>abs(d - d2)) & _U32
            dif[4] = (dif[4] + <unsigned int>abs(d + d2)) & _U32
            dif[5] = (dif[5] + <unsigned int>abs(d - d3)) & _U32
            dif[6] = (dif[6] + <unsigned int>abs(d + d3)) & _U32

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
