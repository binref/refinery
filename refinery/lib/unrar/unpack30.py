"""
RAR 3.0 decompression algorithm.
"""
from __future__ import annotations

import struct
import zlib

from dataclasses import dataclass, field
from typing import Callable

from refinery.lib.unrar.filters import (
    V3FilterType,
    execute_v3_filter,
    identify_v3_filter,
)
from refinery.lib.unrar.reader import BitInput
from refinery.lib.unrar.unpack50 import DecodeTable, decode_number, make_decode_tables

NC30 = 299
DC30 = 60
LDC30 = 17
RC30 = 28
BC30 = 20
HUFF_TABLE_SIZE30 = NC30 + DC30 + RC30 + LDC30

LOW_DIST_REP_COUNT = 16
MAX3_UNPACK_FILTERS = 8192

BLOCK_LZ = 0
BLOCK_PPM = 1

MAX_O = 64
MAX_FREQ = 124
INT_BITS = 7
PERIOD_BITS = 7
TOT_BITS = INT_BITS + PERIOD_BITS
INTERVAL = 1 << INT_BITS
BIN_SCALE = 1 << TOT_BITS

TOP = 1 << 24
BOT = 1 << 15

_M32 = 0xFFFFFFFF

N1 = 4
N2 = 4
N3 = 4
N4 = (128 + 3 - 1 * N1 - 2 * N2 - 3 * N3) // 4
N_INDEXES = N1 + N2 + N3 + N4
UNIT_SIZE = 12
FIXED_UNIT_SIZE = 12

_LDecode = [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224]
_LBits = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5]

_SDDecode = [0, 4, 8, 16, 32, 64, 128, 192]
_SDBits = [2, 2, 3, 4, 5, 6, 6, 6]

ExpEscape = [25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2]


def _init_dist_tables():
    """
    Lazy-initialize DDecode / DBits tables.
    """
    dd = [0] * DC30
    db = [0] * DC30
    db_length_counts = [4, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 14, 0, 12]
    dist = 0
    bit_length = 0
    slot = 0
    for count in db_length_counts:
        for _ in range(count):
            if slot < DC30:
                dd[slot] = dist
                db[slot] = bit_length
                slot += 1
                dist += 1 << bit_length
        bit_length += 1
    return dd, db


_DDecode, _DBits = _init_dist_tables()


def vm_read_data(inp: BitInput) -> int:
    """
    Read a variable-length data value from the VM code stream.
    """
    data = inp.getbits()
    flag = data & 0xC000
    if flag == 0:
        inp.addbits(6)
        return (data >> 10) & 0xF
    elif flag == 0x4000:
        if (data & 0x3C00) == 0:
            val = 0xFFFFFF00 | ((data >> 2) & 0xFF)
            inp.addbits(14)
        else:
            val = (data >> 6) & 0xFF
            inp.addbits(10)
        return val & _M32
    elif flag == 0x8000:
        inp.addbits(2)
        val = inp.getbits()
        inp.addbits(16)
        return val & 0xFFFF
    else:
        inp.addbits(2)
        val = (inp.getbits() << 16) & _M32
        inp.addbits(16)
        val |= inp.getbits()
        inp.addbits(16)
        return val & _M32


class _SubAllocator:
    """
    PPMd sub-allocator.
    Uses a flat bytearray with integer offsets instead of pointers.
    """

    def __init__(self):
        self.heap: bytearray = bytearray()
        self.heap_start = 0
        self.heap_end = 0
        self.p_text = 0
        self.units_start = 0
        self.lo_unit = 0
        self.hi_unit = 0
        self.fake_units_start = 0
        self.glue_count = 0
        self.sub_allocator_size = 0
        self.free_list = [0] * N_INDEXES
        self.indx2units = [0] * N_INDEXES
        self.units2indx = [0] * 128

    def start(self, mb_count: int) -> bool:
        t = mb_count << 20
        if self.sub_allocator_size == t:
            return True
        alloc_size = t // FIXED_UNIT_SIZE * UNIT_SIZE + 2 * UNIT_SIZE
        self.heap = bytearray(alloc_size)
        self.heap_start = 0
        self.heap_end = alloc_size - UNIT_SIZE
        self.sub_allocator_size = t
        return True

    def stop(self):
        self.sub_allocator_size = 0
        self.heap = bytearray()

    def init(self):
        self.free_list = [0] * N_INDEXES
        self.p_text = self.heap_start

        size2 = FIXED_UNIT_SIZE * (self.sub_allocator_size // 8 // FIXED_UNIT_SIZE * 7)
        real_size2 = size2 // FIXED_UNIT_SIZE * UNIT_SIZE
        size1 = self.sub_allocator_size - size2
        real_size1 = size1 // FIXED_UNIT_SIZE * UNIT_SIZE + UNIT_SIZE

        self.lo_unit = self.units_start = self.heap_start + real_size1
        self.fake_units_start = self.heap_start + size1
        self.hi_unit = self.lo_unit + real_size2

        i = 0
        k = 1
        for _ in range(N1):
            self.indx2units[i] = k
            i += 1
            k += 1
        k += 1
        for _ in range(N2):
            self.indx2units[i] = k
            i += 1
            k += 2
        k += 1
        for _ in range(N3):
            self.indx2units[i] = k
            i += 1
            k += 3
        k += 1
        for _ in range(N4):
            self.indx2units[i] = k
            i += 1
            k += 4

        self.glue_count = 0
        k = 0
        i = 0
        for j in range(128):
            if i < N_INDEXES and self.indx2units[i] < j + 1:
                i += 1
            self.units2indx[j] = min(i, N_INDEXES - 1)

    def _u2b(self, nu: int) -> int:
        return UNIT_SIZE * nu

    def _insert_node(self, p: int, indx: int):
        struct.pack_into('<I', self.heap, p, self.free_list[indx])
        self.free_list[indx] = p

    def _remove_node(self, indx: int) -> int:
        ret = self.free_list[indx]
        self.free_list[indx] = struct.unpack_from('<I', self.heap, ret)[0]
        return ret

    def _split_block(self, pv: int, old_indx: int, new_indx: int):
        u_diff = self.indx2units[old_indx] - self.indx2units[new_indx]
        p = pv + self._u2b(self.indx2units[new_indx])
        i = self.units2indx[u_diff - 1] if u_diff > 0 else 0
        if i < N_INDEXES and self.indx2units[i] != u_diff:
            i -= 1
            self._insert_node(p, i)
            p += self._u2b(self.indx2units[i])
            u_diff -= self.indx2units[i]
        if u_diff > 0:
            self._insert_node(p, self.units2indx[u_diff - 1])

    def alloc_context(self) -> int:
        if self.hi_unit != self.lo_unit:
            self.hi_unit -= UNIT_SIZE
            return self.hi_unit
        if self.free_list[0]:
            return self._remove_node(0)
        return self._alloc_units_rare(0)

    def alloc_units(self, nu: int) -> int:
        indx = self.units2indx[min(nu - 1, 127)]
        if self.free_list[indx]:
            return self._remove_node(indx)
        ret = self.lo_unit
        self.lo_unit += self._u2b(self.indx2units[indx])
        if self.lo_unit <= self.hi_unit:
            return ret
        self.lo_unit -= self._u2b(self.indx2units[indx])
        return self._alloc_units_rare(indx)

    def _alloc_units_rare(self, indx: int) -> int:
        if not self.glue_count:
            self.glue_count = 255
            self._glue_free_blocks()
            if self.free_list[indx]:
                return self._remove_node(indx)
        i = indx
        while True:
            i += 1
            if i == N_INDEXES:
                self.glue_count -= 1
                i_bytes = self._u2b(self.indx2units[indx])
                j = FIXED_UNIT_SIZE * self.indx2units[indx]
                if self.fake_units_start - self.p_text > j:
                    self.fake_units_start -= j
                    self.units_start -= i_bytes
                    return self.units_start
                return 0
            if self.free_list[i]:
                break
        ret = self._remove_node(i)
        self._split_block(ret, i, indx)
        return ret

    def _glue_free_blocks(self):
        all_blocks: list[tuple[int, int]] = []
        for i in range(N_INDEXES):
            while self.free_list[i]:
                p = self._remove_node(i)
                all_blocks.append((p, self.indx2units[i]))
        all_blocks.sort()
        merged: list[tuple[int, int]] = []
        for addr, nu in all_blocks:
            if merged and merged[-1][0] + self._u2b(merged[-1][1]) == addr:
                merged[-1] = (merged[-1][0], merged[-1][1] + nu)
            else:
                merged.append((addr, nu))
        for addr, nu in merged:
            while nu > 128:
                self._insert_node(addr, N_INDEXES - 1)
                addr += self._u2b(128)
                nu -= 128
            if nu > 0:
                idx = self.units2indx[min(nu - 1, 127)]
                if idx < N_INDEXES and self.indx2units[idx] != nu:
                    k = nu - self.indx2units[idx - 1] if idx > 0 else nu
                    if k > 0 and k <= 128:
                        p2 = addr + self._u2b(nu - k)
                        self._insert_node(p2, self.units2indx[min(k - 1, 127)])
                    if idx > 0:
                        idx -= 1
                self._insert_node(addr, idx)

    def expand_units(self, old_ptr: int, old_nu: int) -> int:
        i0 = self.units2indx[min(old_nu - 1, 127)]
        i1 = self.units2indx[min(old_nu, 127)]
        if i0 == i1:
            return old_ptr
        ptr = self.alloc_units(old_nu + 1)
        if ptr:
            size = self._u2b(old_nu)
            self.heap[ptr:ptr + size] = self.heap[old_ptr:old_ptr + size]
            self._insert_node(old_ptr, i0)
        return ptr

    def shrink_units(self, old_ptr: int, old_nu: int, new_nu: int) -> int:
        i0 = self.units2indx[min(old_nu - 1, 127)]
        i1 = self.units2indx[min(new_nu - 1, 127)]
        if i0 == i1:
            return old_ptr
        if self.free_list[i1]:
            ptr = self._remove_node(i1)
            size = self._u2b(new_nu)
            self.heap[ptr:ptr + size] = self.heap[old_ptr:old_ptr + size]
            self._insert_node(old_ptr, i0)
            return ptr
        else:
            self._split_block(old_ptr, i0, i1)
            return old_ptr

    def free_units(self, ptr: int, old_nu: int):
        self._insert_node(ptr, self.units2indx[min(old_nu - 1, 127)])

    @property
    def allocated(self) -> int:
        return self.sub_allocator_size


_STATE_SIZE = 6
_CTX_SIZE = 12


class _PPMHeap:
    """
    Accessor for PPM structures stored in sub-allocator heap.
    """

    def __init__(self, sa: _SubAllocator):
        self.sa = sa
        self.h = sa.heap

    def st_symbol(self, p: int) -> int:
        return self.h[p]

    def st_set_symbol(self, p: int, v: int):
        self.h[p] = v & 0xFF

    def st_freq(self, p: int) -> int:
        return self.h[p + 1]

    def st_set_freq(self, p: int, v: int):
        self.h[p + 1] = v & 0xFF

    def st_successor(self, p: int) -> int:
        return struct.unpack_from('<I', self.h, p + 2)[0]

    def st_set_successor(self, p: int, v: int):
        struct.pack_into('<I', self.h, p + 2, v & _M32)

    def st_copy(self, dst: int, src: int):
        self.h[dst:dst + _STATE_SIZE] = self.h[src:src + _STATE_SIZE]

    def st_swap(self, a: int, b: int):
        t = self.h[a:a + _STATE_SIZE]
        self.h[a:a + _STATE_SIZE] = self.h[b:b + _STATE_SIZE]
        self.h[b:b + _STATE_SIZE] = t

    def ctx_num_stats(self, c: int) -> int:
        return struct.unpack_from('<H', self.h, c)[0]

    def ctx_set_num_stats(self, c: int, v: int):
        struct.pack_into('<H', self.h, c, v & 0xFFFF)

    def ctx_summ_freq(self, c: int) -> int:
        return struct.unpack_from('<H', self.h, c + 2)[0]

    def ctx_set_summ_freq(self, c: int, v: int):
        struct.pack_into('<H', self.h, c + 2, v & 0xFFFF)

    def ctx_stats(self, c: int) -> int:
        return struct.unpack_from('<I', self.h, c + 4)[0]

    def ctx_set_stats(self, c: int, v: int):
        struct.pack_into('<I', self.h, c + 4, v & _M32)

    def ctx_one_state(self, c: int) -> int:
        """
        Return offset of the OneState within context (starts at c+2).
        """
        return c + 2

    def ctx_suffix(self, c: int) -> int:
        return struct.unpack_from('<I', self.h, c + 8)[0]

    def ctx_set_suffix(self, c: int, v: int):
        struct.pack_into('<I', self.h, c + 8, v & _M32)

    def state_at(self, stats: int, i: int) -> int:
        return stats + i * _STATE_SIZE


class _SEE2Context:
    __slots__ = ('summ', 'shift', 'count')

    def __init__(self, init_val: int = 0):
        self.summ = 0
        self.shift = 0
        self.count = 0
        if init_val:
            self.init(init_val)

    def init(self, init_val: int):
        self.shift = PERIOD_BITS - 4
        self.summ = (init_val << self.shift) & 0xFFFF
        self.count = 4

    def get_mean(self) -> int:
        ret = (self.summ & 0xFFFF) >> self.shift
        self.summ = (self.summ - ret) & 0xFFFF
        return ret + (1 if ret == 0 else 0)

    def update(self):
        if self.shift < PERIOD_BITS:
            self.count -= 1
            if self.count == 0:
                self.summ = (self.summ + self.summ) & 0xFFFF
                self.count = 3 << self.shift
                self.shift += 1


class _RangeCoder:
    __slots__ = (
        'low',
        'code',
        'range',
        'low_count',
        'high_count',
        'scale',
        '_reader',
    )

    _reader: Callable[[], int]

    def __init__(self):
        self.low = 0
        self.code = 0
        self.range = _M32
        self.low_count = 0
        self.high_count = 0
        self.scale = 0

    def init_decoder(self, reader: Callable[[], int]):
        """
        Initialize from a byte reader (callable returning int).
        """
        self._reader = reader
        self.low = 0
        self.code = 0
        self.range = _M32
        for _ in range(4):
            self.code = ((self.code << 8) | (self._reader() & 0xFF)) & _M32

    def _get_char(self) -> int:
        return self._reader() & 0xFF

    def get_current_count(self) -> int:
        self.range = (self.range // self.scale) & _M32
        if self.range == 0:
            self.range = 1
        return ((self.code - self.low) & _M32) // self.range

    def get_current_shift_count(self, shift: int) -> int:
        self.range = (self.range >> shift) & _M32
        if self.range == 0:
            self.range = 1
        return ((self.code - self.low) & _M32) // self.range

    def decode(self):
        self.low = (self.low + self.range * self.low_count) & _M32
        self.range = (self.range * (self.high_count - self.low_count)) & _M32

    def normalize(self):
        while True:
            if ((self.low ^ ((self.low + self.range) & _M32)) & _M32) >= TOP:
                if (self.range & _M32) >= BOT:
                    break
                self.range = ((-(self.low & 0xFFFFFFFF)) & (BOT - 1)) & _M32
            self.code = ((self.code << 8) | self._get_char()) & _M32
            self.range = (self.range << 8) & _M32
            self.low = (self.low << 8) & _M32


class _ModelPPM:
    """
    PPMd Model H for RAR3 decompression.
    """

    def __init__(self):
        self.sa = _SubAllocator()
        self.hp: _PPMHeap = _PPMHeap(self.sa)
        self.coder = _RangeCoder()
        self.min_context = 0
        self.max_context = 0
        self.found_state = 0
        self.num_masked = 0
        self.init_esc = 0
        self.order_fall = 0
        self.max_order = 0
        self.run_length = 0
        self.init_rl = 0
        self.esc_count = 0
        self.prev_success = 0
        self.hi_bits_flag = 0
        self.char_mask = [0] * 256
        self.ns2indx = [0] * 256
        self.ns2bs_indx = [0] * 256
        self.hb2flag = [0] * 256
        self.bin_summ = [[0] * 64 for _ in range(128)]
        self.see2_cont = [[_SEE2Context() for _ in range(16)] for _ in range(25)]
        self.dummy_see2 = _SEE2Context()

    def _restart_model_rare(self):
        hp = self.hp
        sa = self.sa
        self.char_mask = [0] * 256
        sa.init()
        self.init_rl = -(min(self.max_order, 12)) - 1
        self.min_context = self.max_context = sa.alloc_context()
        if not self.min_context:
            return
        hp.ctx_set_suffix(self.min_context, 0)
        self.order_fall = self.max_order

        hp.ctx_set_num_stats(self.min_context, 256)
        hp.ctx_set_summ_freq(self.min_context, 257)

        stats = sa.alloc_units(128)
        if not stats:
            return
        hp.ctx_set_stats(self.min_context, stats)
        self.found_state = stats

        self.run_length = self.init_rl
        self.prev_success = 0
        for i in range(256):
            s = hp.state_at(stats, i)
            hp.st_set_symbol(s, i)
            hp.st_set_freq(s, 1)
            hp.st_set_successor(s, 0)

        init_bin_esc = [0x3CDD, 0x1F3F, 0x59BF, 0x48F3, 0x64A1, 0x5ABC, 0x6632, 0x6051]
        for i in range(128):
            for k in range(8):
                for m in range(0, 64, 8):
                    self.bin_summ[i][k + m] = BIN_SCALE - init_bin_esc[k] // (i + 2)

        for i in range(25):
            for k in range(16):
                self.see2_cont[i][k].init(5 * i + 10)

    def _start_model_rare(self, max_order: int):
        self.esc_count = 1
        self.max_order = max_order
        self._restart_model_rare()

        self.ns2bs_indx[0] = 0
        self.ns2bs_indx[1] = 2
        for i in range(2, 11):
            self.ns2bs_indx[i] = 4
        for i in range(11, 256):
            self.ns2bs_indx[i] = 6

        for i in range(3):
            self.ns2indx[i] = i
        m = 3
        step = 1
        k = step
        for i in range(3, 256):
            self.ns2indx[i] = m
            k -= 1
            if k == 0:
                step += 1
                k = step
                m += 1

        for i in range(0x40):
            self.hb2flag[i] = 0
        for i in range(0x40, 0x100):
            self.hb2flag[i] = 0x08

        self.dummy_see2.shift = PERIOD_BITS

    def decode_init(self, byte_reader: Callable[[], int], esc_char_ref: list) -> bool:
        """
        Initialize PPM decoding. esc_char_ref is [esc_char] mutable.
        """
        max_order = byte_reader()
        if max_order < 0:
            return False
        reset = bool(max_order & 0x20)
        max_mb = 0
        if reset:
            max_mb = byte_reader()
            if max_mb < 0:
                return False
        elif self.sa.allocated == 0:
            return False

        if max_order & 0x40:
            ch = byte_reader()
            if ch < 0:
                return False
            esc_char_ref[0] = ch

        self.coder.init_decoder(byte_reader)

        if reset:
            order = (max_order & 0x1F) + 1
            if order > 16:
                order = 16 + (order - 16) * 3
            if order == 1:
                self.sa.stop()
                return False
            self.sa.start(max_mb + 1)
            self.hp = _PPMHeap(self.sa)
            self._start_model_rare(order)

        return self.min_context != 0

    def decode_char(self) -> int:
        """
        Decode one character. Returns -1 on error.
        """
        hp = self.hp
        sa = self.sa

        if not hp or not self.min_context:
            return -1
        if self.min_context >= sa.heap_end or self.min_context < sa.p_text:
            return -1

        if hp.ctx_num_stats(self.min_context) != 1:
            stats = hp.ctx_stats(self.min_context)
            if stats < sa.p_text or stats >= sa.heap_end:
                return -1
            if not self._decode_symbol1(self.min_context):
                return -1
        else:
            self._decode_bin_symbol(self.min_context)

        self.coder.decode()

        while not self.found_state:
            self.coder.normalize()
            while True:
                self.order_fall += 1
                self.min_context = hp.ctx_suffix(self.min_context)
                if not self.min_context or self.min_context < sa.p_text or self.min_context >= sa.heap_end:
                    return -1
                if hp.ctx_num_stats(self.min_context) != self.num_masked:
                    break
            if not self._decode_symbol2(self.min_context):
                return -1
            self.coder.decode()

        symbol = hp.st_symbol(self.found_state)
        if not self.order_fall and hp.st_successor(self.found_state) > sa.p_text:
            self.min_context = self.max_context = hp.st_successor(self.found_state)
        else:
            self._update_model()
            if self.esc_count == 0:
                self._clear_mask()

        self.coder.normalize()
        return symbol

    def _decode_bin_symbol(self, ctx: int):
        hp = self.hp
        os = hp.ctx_one_state(ctx)
        rs_freq = hp.st_freq(os)
        rs_symbol = hp.st_symbol(os)
        suffix = hp.ctx_suffix(ctx)

        self.hi_bits_flag = self.hb2flag[hp.st_symbol(self.found_state)] if self.found_state else 0
        ns = hp.ctx_num_stats(suffix) if suffix else 1

        bs_idx = (rs_freq - 1) & 0x7F
        bs_off = (
            self.prev_success + self.ns2bs_indx[min(ns - 1, 255)]
            + self.hi_bits_flag + 2 * self.hb2flag[rs_symbol]
            + ((self.run_length >> 26) & 0x20)
        )
        bs_off = min(bs_off, 63)

        bs = self.bin_summ[bs_idx][bs_off]
        if self.coder.get_current_shift_count(TOT_BITS) < bs:
            self.found_state = os
            if rs_freq < 128:
                hp.st_set_freq(os, rs_freq + 1)
            self.coder.low_count = 0
            self.coder.high_count = bs
            self.bin_summ[bs_idx][bs_off] = min(bs + INTERVAL - self._get_mean(bs, PERIOD_BITS, 2), 0xFFFF) & 0xFFFF
            self.prev_success = 1
            self.run_length += 1
        else:
            self.coder.low_count = bs
            bs = max(bs - self._get_mean(bs, PERIOD_BITS, 2), 0) & 0xFFFF
            self.bin_summ[bs_idx][bs_off] = bs
            self.coder.high_count = BIN_SCALE
            self.init_esc = ExpEscape[min(bs >> 10, 15)]
            self.num_masked = 1
            self.char_mask[rs_symbol] = self.esc_count
            self.prev_success = 0
            self.found_state = 0

    @staticmethod
    def _get_mean(summ: int, shift: int, rnd: int) -> int:
        return (summ + (1 << (shift - rnd))) >> shift

    def _decode_symbol1(self, ctx: int) -> bool:
        hp = self.hp
        self.coder.scale = hp.ctx_summ_freq(ctx)
        stats = hp.ctx_stats(ctx)
        count = self.coder.get_current_count()
        if count >= self.coder.scale:
            return False

        p = stats
        hi_cnt = hp.st_freq(p)

        if count < hi_cnt:
            self.prev_success = 1 if (2 * hi_cnt > self.coder.scale) else 0
            self.coder.high_count = hi_cnt
            self.run_length += self.prev_success
            self.found_state = p
            hi_cnt += 4
            hp.st_set_freq(p, min(hi_cnt, 255))
            summ_freq = hp.ctx_summ_freq(ctx) + 4
            hp.ctx_set_summ_freq(ctx, min(summ_freq, 0xFFFF))
            if hi_cnt > MAX_FREQ:
                self._rescale(ctx)
            self.coder.low_count = 0
            return True
        elif not self.found_state:
            return False

        self.prev_success = 0
        num_stats = hp.ctx_num_stats(ctx)
        i = num_stats - 1
        while i > 0:
            p += _STATE_SIZE
            hi_cnt += hp.st_freq(p)
            if hi_cnt > count:
                break
            i -= 1
        else:
            if hi_cnt <= count:
                self.hi_bits_flag = self.hb2flag[hp.st_symbol(self.found_state)] if self.found_state else 0
                self.coder.low_count = hi_cnt
                self.char_mask[hp.st_symbol(p)] = self.esc_count
                self.num_masked = num_stats
                i = num_stats - 1
                self.found_state = 0
                while i > 0:
                    p -= _STATE_SIZE
                    self.char_mask[hp.st_symbol(p)] = self.esc_count
                    i -= 1
                self.coder.high_count = self.coder.scale
                return True

        self.coder.low_count = hi_cnt - hp.st_freq(p)
        self.coder.high_count = hi_cnt
        self._update1(ctx, p)
        return True

    def _update1(self, ctx: int, p: int):
        hp = self.hp
        self.found_state = p
        freq = hp.st_freq(p) + 4
        hp.st_set_freq(p, min(freq, 255))
        summ = hp.ctx_summ_freq(ctx) + 4
        hp.ctx_set_summ_freq(ctx, min(summ, 0xFFFF))

        stats = hp.ctx_stats(ctx)
        if p > stats and hp.st_freq(p) > hp.st_freq(p - _STATE_SIZE):
            hp.st_swap(p, p - _STATE_SIZE)
            self.found_state = p - _STATE_SIZE
            p = self.found_state
            if hp.st_freq(p) > MAX_FREQ:
                self._rescale(ctx)

    def _decode_symbol2(self, ctx: int) -> bool:
        hp = self.hp
        num_stats = hp.ctx_num_stats(ctx)
        diff = num_stats - self.num_masked

        see2c = self._make_esc_freq2(ctx, diff)
        stats = hp.ctx_stats(ctx)

        ps = []
        hi_cnt = 0
        p = stats - _STATE_SIZE
        i = diff
        while i > 0:
            p += _STATE_SIZE
            while self.char_mask[hp.st_symbol(p)] == self.esc_count:
                p += _STATE_SIZE
            hi_cnt += hp.st_freq(p)
            ps.append(p)
            i -= 1

        self.coder.scale += hi_cnt
        count = self.coder.get_current_count()
        if count >= self.coder.scale:
            return False

        if count < hi_cnt:
            hi2 = 0
            idx = 0
            p = ps[0]
            while True:
                hi2 += hp.st_freq(p)
                if hi2 > count:
                    break
                idx += 1
                if idx >= len(ps):
                    return False
                p = ps[idx]
            self.coder.low_count = hi2 - hp.st_freq(p)
            self.coder.high_count = hi2
            if see2c is not self.dummy_see2:
                see2c.update()
            self._update2(ctx, p)
        else:
            self.coder.low_count = hi_cnt
            self.coder.high_count = self.coder.scale
            i = diff
            for pp in ps:
                self.char_mask[hp.st_symbol(pp)] = self.esc_count
            if see2c is not self.dummy_see2:
                see2c.summ = (see2c.summ + self.coder.scale) & 0xFFFF
            self.num_masked = num_stats
        return True

    def _update2(self, ctx: int, p: int):
        hp = self.hp
        self.found_state = p
        freq = hp.st_freq(p) + 4
        hp.st_set_freq(p, min(freq, 255))
        summ = hp.ctx_summ_freq(ctx) + 4
        hp.ctx_set_summ_freq(ctx, min(summ, 0xFFFF))
        if hp.st_freq(p) > MAX_FREQ:
            self._rescale(ctx)
        self.esc_count += 1
        self.run_length = self.init_rl

    def _make_esc_freq2(self, ctx: int, diff: int) -> _SEE2Context:
        hp = self.hp
        num_stats = hp.ctx_num_stats(ctx)
        if num_stats != 256:
            ns_idx = self.ns2indx[min(diff - 1, 255)]
            suffix = hp.ctx_suffix(ctx)
            suffix_ns = hp.ctx_num_stats(suffix) if suffix else 1
            off = (
                int(diff < suffix_ns - num_stats)
                + 2 * int(hp.ctx_summ_freq(ctx) < 11 * num_stats)
                + 4 * int(self.num_masked > diff)
                + self.hi_bits_flag
            )
            off = min(off, 15)
            psee2c = self.see2_cont[min(ns_idx, 24)][off]
            self.coder.scale = psee2c.get_mean()
            return psee2c
        else:
            self.coder.scale = 1
            return self.dummy_see2

    def _rescale(self, ctx: int):
        hp = self.hp
        sa = self.sa
        num_stats = hp.ctx_num_stats(ctx)
        stats = hp.ctx_stats(ctx)

        if self.found_state and self.found_state != stats:
            p = self.found_state
            while p > stats:
                hp.st_swap(p, p - _STATE_SIZE)
                p -= _STATE_SIZE

        freq0 = hp.st_freq(stats)
        hp.st_set_freq(stats, min(freq0 + 4, 255))
        summ_freq = hp.ctx_summ_freq(ctx) + 4
        esc_freq = summ_freq - hp.st_freq(stats)
        adder = 1 if self.order_fall != 0 else 0

        new_freq = ((hp.st_freq(stats) + adder) >> 1)
        hp.st_set_freq(stats, max(new_freq, 1))
        new_summ = hp.st_freq(stats)

        i = num_stats - 1
        p = stats + _STATE_SIZE
        while i > 0:
            esc_freq -= hp.st_freq(p)
            f = ((hp.st_freq(p) + adder) >> 1)
            f = max(f, 0)
            hp.st_set_freq(p, f)
            new_summ += f
            if f > hp.st_freq(p - _STATE_SIZE):
                tmp = hp.h[p:p + _STATE_SIZE]
                q = p
                while q > stats and f > hp.st_freq(q - _STATE_SIZE):
                    hp.st_copy(q, q - _STATE_SIZE)
                    q -= _STATE_SIZE
                hp.h[q:q + _STATE_SIZE] = tmp
            p += _STATE_SIZE
            i -= 1

        p = stats + (num_stats - 1) * _STATE_SIZE
        zero_count = 0
        while p > stats and hp.st_freq(p) == 0:
            zero_count += 1
            p -= _STATE_SIZE

        if zero_count > 0:
            esc_freq += zero_count
            num_stats -= zero_count
            hp.ctx_set_num_stats(ctx, num_stats)
            if num_stats == 1:
                tmp_sym = hp.st_symbol(stats)
                tmp_freq = hp.st_freq(stats)
                tmp_succ = hp.st_successor(stats)
                while tmp_freq > 1 and esc_freq > 1:
                    tmp_freq -= tmp_freq >> 1
                    esc_freq >>= 1
                old_nu = ((num_stats + zero_count) + 1) >> 1
                sa.free_units(stats, old_nu)
                os = hp.ctx_one_state(ctx)
                hp.st_set_symbol(os, tmp_sym)
                hp.st_set_freq(os, tmp_freq)
                hp.st_set_successor(os, tmp_succ)
                self.found_state = os
                return
            else:
                old_n = ((num_stats + zero_count) + 1) >> 1
                new_n = (num_stats + 1) >> 1
                if old_n != new_n:
                    new_stats = sa.shrink_units(stats, old_n, new_n)
                    hp.ctx_set_stats(ctx, new_stats)
                    stats = new_stats

        esc_freq -= esc_freq >> 1
        new_summ += max(esc_freq, 1)
        hp.ctx_set_summ_freq(ctx, min(new_summ, 0xFFFF))
        self.found_state = hp.ctx_stats(ctx)

    def _create_successors(self, skip: bool, p1: int) -> int:
        hp = self.hp
        sa = self.sa
        pc = self.min_context
        up_branch = hp.st_successor(self.found_state)

        ps = []

        if not skip:
            ps.append(self.found_state)
            if not hp.ctx_suffix(pc):
                p1 = 0

        if p1:
            p = p1
            pc = hp.ctx_suffix(pc)
            if hp.st_successor(p) != up_branch:
                pc = hp.st_successor(p)
            else:
                if len(ps) >= MAX_O:
                    return 0
                ps.append(p)
                while hp.ctx_suffix(pc):
                    pc = hp.ctx_suffix(pc)
                    if hp.ctx_num_stats(pc) != 1:
                        p = hp.ctx_stats(pc)
                        if hp.st_symbol(p) != hp.st_symbol(self.found_state):
                            while hp.st_symbol(p) != hp.st_symbol(self.found_state):
                                p += _STATE_SIZE
                    else:
                        p = hp.ctx_one_state(pc)
                    if hp.st_successor(p) != up_branch:
                        pc = hp.st_successor(p)
                        break
                    if len(ps) >= MAX_O:
                        return 0
                    ps.append(p)
        elif hp.ctx_suffix(pc):
            pc = hp.ctx_suffix(pc)
            while True:
                if hp.ctx_num_stats(pc) != 1:
                    p = hp.ctx_stats(pc)
                    if hp.st_symbol(p) != hp.st_symbol(self.found_state):
                        while hp.st_symbol(p) != hp.st_symbol(self.found_state):
                            p += _STATE_SIZE
                else:
                    p = hp.ctx_one_state(pc)
                if hp.st_successor(p) != up_branch:
                    pc = hp.st_successor(p)
                    break
                if len(ps) >= MAX_O:
                    return 0
                ps.append(p)
                if not hp.ctx_suffix(pc):
                    break
                pc = hp.ctx_suffix(pc)

        if len(ps) == 0:
            return pc

        if up_branch >= len(hp.h) or up_branch < 1:
            return 0
        up_symbol = hp.h[up_branch] if up_branch < len(hp.h) else 0
        up_successor = up_branch + 1

        if hp.ctx_num_stats(pc) != 1:
            if pc <= sa.p_text:
                return 0
            stats = hp.ctx_stats(pc)
            pp = stats
            if hp.st_symbol(pp) != up_symbol:
                while hp.st_symbol(pp) != up_symbol:
                    pp += _STATE_SIZE
            cf = hp.st_freq(pp) - 1
            s0 = hp.ctx_summ_freq(pc) - hp.ctx_num_stats(pc) - cf
            if s0 <= 0:
                up_freq = 1
            elif 2 * cf <= s0:
                up_freq = 1 + (1 if 5 * cf > s0 else 0)
            else:
                up_freq = 1 + min((2 * cf + 3 * s0 - 1) // (2 * s0), 255)
        else:
            up_freq = hp.st_freq(hp.ctx_one_state(pc))

        while ps:
            p_state = ps.pop()
            new_ctx = sa.alloc_context()
            if not new_ctx:
                return 0
            hp.ctx_set_num_stats(new_ctx, 1)
            os = hp.ctx_one_state(new_ctx)
            hp.st_set_symbol(os, up_symbol)
            hp.st_set_freq(os, up_freq)
            hp.st_set_successor(os, up_successor)
            hp.ctx_set_suffix(new_ctx, pc)
            hp.st_set_successor(p_state, new_ctx)
            pc = new_ctx

        return pc

    def _update_model(self):
        hp = self.hp
        sa = self.sa

        fs_symbol = hp.st_symbol(self.found_state)
        fs_freq = hp.st_freq(self.found_state)
        fs_successor = hp.st_successor(self.found_state)

        p = 0
        suffix = hp.ctx_suffix(self.min_context)
        if fs_freq < MAX_FREQ // 4 and suffix:
            if hp.ctx_num_stats(suffix) != 1:
                stats = hp.ctx_stats(suffix)
                p = stats
                if hp.st_symbol(p) != fs_symbol:
                    while hp.st_symbol(p) != fs_symbol:
                        p += _STATE_SIZE
                    if hp.st_freq(p) >= hp.st_freq(p - _STATE_SIZE):
                        hp.st_swap(p, p - _STATE_SIZE)
                        p -= _STATE_SIZE
                if hp.st_freq(p) < MAX_FREQ - 9:
                    hp.st_set_freq(p, hp.st_freq(p) + 2)
                    summ = hp.ctx_summ_freq(suffix) + 2
                    hp.ctx_set_summ_freq(suffix, min(summ, 0xFFFF))
            else:
                p = hp.ctx_one_state(suffix)
                if hp.st_freq(p) < 32:
                    hp.st_set_freq(p, hp.st_freq(p) + 1)

        if not self.order_fall:
            successor = self._create_successors(True, p)
            if not successor:
                self._restart_model_rare()
                self.esc_count = 0
                return
            self.min_context = self.max_context = successor
            hp.st_set_successor(self.found_state, successor)
            return

        if sa.p_text < len(sa.heap):
            sa.heap[sa.p_text] = fs_symbol & 0xFF
        sa.p_text += 1
        successor_ptr = sa.p_text

        if sa.p_text >= sa.fake_units_start:
            self._restart_model_rare()
            self.esc_count = 0
            return

        if fs_successor:
            if fs_successor <= sa.p_text:
                new_succ = self._create_successors(False, p)
                if not new_succ:
                    self._restart_model_rare()
                    self.esc_count = 0
                    return
                hp.st_set_successor(self.found_state, new_succ)
                fs_successor = new_succ
            self.order_fall -= 1
            if not self.order_fall:
                successor_ptr = fs_successor
                sa.p_text -= int(self.max_context != self.min_context)
        else:
            hp.st_set_successor(self.found_state, successor_ptr)
            fs_successor = self.min_context

        ns = hp.ctx_num_stats(self.min_context)
        s0 = hp.ctx_summ_freq(self.min_context) - ns - (fs_freq - 1)
        if s0 < 1:
            s0 = 1

        pc = self.max_context
        while pc != self.min_context:
            ns1 = hp.ctx_num_stats(pc)
            if ns1 != 1:
                if (ns1 & 1) == 0:
                    new_stats = sa.expand_units(hp.ctx_stats(pc), ns1 >> 1)
                    if not new_stats:
                        self._restart_model_rare()
                        self.esc_count = 0
                        return
                    hp.ctx_set_stats(pc, new_stats)
                summ = hp.ctx_summ_freq(pc)
                summ += int(2 * ns1 < ns) + 2 * int((4 * ns1 <= ns) and (summ <= 8 * ns1))
                hp.ctx_set_summ_freq(pc, min(summ, 0xFFFF))
            else:
                pp = sa.alloc_units(1)
                if not pp:
                    self._restart_model_rare()
                    self.esc_count = 0
                    return
                os = hp.ctx_one_state(pc)
                hp.h[pp:pp + _STATE_SIZE] = hp.h[os:os + _STATE_SIZE]
                hp.ctx_set_stats(pc, pp)
                f = hp.st_freq(pp)
                if f < MAX_FREQ // 4 - 1:
                    hp.st_set_freq(pp, min(f + f, 255))
                else:
                    hp.st_set_freq(pp, MAX_FREQ - 4)
                summ = hp.st_freq(pp) + self.init_esc + int(ns > 3)
                hp.ctx_set_summ_freq(pc, min(summ, 0xFFFF))

            cf = 2 * fs_freq * (hp.ctx_summ_freq(pc) + 6)
            sf = s0 + hp.ctx_summ_freq(pc)
            if cf < 6 * sf:
                new_cf = 1 + int(cf > sf) + int(cf >= 4 * sf)
                summ = hp.ctx_summ_freq(pc) + 3
                hp.ctx_set_summ_freq(pc, min(summ, 0xFFFF))
            else:
                new_cf = 4 + int(cf >= 9 * sf) + int(cf >= 12 * sf) + int(cf >= 15 * sf)
                summ = hp.ctx_summ_freq(pc) + new_cf
                hp.ctx_set_summ_freq(pc, min(summ, 0xFFFF))

            new_state = hp.state_at(hp.ctx_stats(pc), ns1)
            hp.st_set_successor(new_state, successor_ptr)
            hp.st_set_symbol(new_state, fs_symbol)
            hp.st_set_freq(new_state, new_cf)
            hp.ctx_set_num_stats(pc, ns1 + 1)

            pc = hp.ctx_suffix(pc)

        self.max_context = self.min_context = fs_successor

    def _clear_mask(self):
        self.esc_count = 1
        self.char_mask = [0] * 256

    def cleanup(self):
        self.sa.stop()
        self.sa.start(1)
        self.hp = _PPMHeap(self.sa)
        self._start_model_rare(2)


@dataclass
class _UnpackFilter30:
    block_start: int = 0
    block_length: int = 0
    next_window: bool = False
    parent_filter: int = 0
    prg_type: V3FilterType = V3FilterType.VMSF_NONE
    init_r: list[int] = field(default_factory=lambda: [0] * 8)


class Unpack30:
    """
    RAR 3.0 decompression engine.
    """

    def __init__(
        self,
        data: bytes | memoryview,
        unp_size: int,
        win_size: int,
        solid: bool = False,
    ):
        self._inp = BitInput(data)
        self._dest_size = unp_size
        self._win_size = max(win_size, 0x40000)
        self._win_mask = self._win_size - 1
        self._window = bytearray(self._win_size)
        self._solid = solid
        self._old_dist = [0, 0, 0, 0]
        self._last_length = 0
        self._unp_ptr = 0
        self._wr_ptr = 0
        self._written = 0
        self._output = bytearray()
        self._tables_read = False
        self._block_type = BLOCK_LZ
        self._block_tables = _BlockTables30()
        self._unp_old_table = bytearray(HUFF_TABLE_SIZE30)
        self._ppm = _ModelPPM()
        self._ppm_esc_char = 2
        self._prev_low_dist = 0
        self._low_dist_rep_count = 0
        self._filters: list[_UnpackFilter30] = []
        self._old_filter_lengths: list[int] = []
        self._prgstack: list[_UnpackFilter30 | None] = []
        self._last_filter = 0

    def _get_char(self) -> int:
        inp = self._inp
        if inp.in_addr >= len(inp.buf):
            return 0
        ch = inp.buf[inp.in_addr]
        inp.in_addr += 1
        return ch

    def _insert_old_dist(self, distance: int):
        self._old_dist[3] = self._old_dist[2]
        self._old_dist[2] = self._old_dist[1]
        self._old_dist[1] = self._old_dist[0]
        self._old_dist[0] = distance

    def _copy_string(self, length: int, distance: int):
        mask = self._win_mask
        win = self._window
        src = self._unp_ptr - distance
        dst = self._unp_ptr
        while length > 0:
            win[dst & mask] = win[src & mask]
            src += 1
            dst += 1
            length -= 1
        self._unp_ptr = dst & mask

    def _write_data(self, data: memoryview | bytes | bytearray):
        remaining = self._dest_size - self._written
        if remaining <= 0:
            return
        write_size = min(len(data), remaining)
        self._output.extend(data[:write_size])
        self._written += write_size

    def _write_area(self, start: int, end: int):
        win = self._window
        if end < start:
            self._write_data(win[start:self._win_size])
            self._write_data(win[:end])
        elif end > start:
            self._write_data(win[start:end])

    def _write_buf(self):
        written_border = self._wr_ptr
        mask = self._win_mask
        write_size = (self._unp_ptr - written_border) & mask

        for i, flt in enumerate(self._prgstack):
            if flt is None:
                continue
            if flt.next_window:
                flt.next_window = False
                continue

            block_start = flt.block_start
            block_length = flt.block_length

            if ((block_start - written_border) & mask) < write_size:
                if written_border != block_start:
                    self._write_area(written_border, block_start)
                    written_border = block_start
                    write_size = (self._unp_ptr - written_border) & mask

                if block_length <= write_size:
                    block_end = (block_start + block_length) & mask
                    mem = bytearray(block_length)
                    if block_start < block_end or block_end == 0:
                        mem[:] = self._window[block_start:block_start + block_length]
                    else:
                        first = self._win_size - block_start
                        mem[:first] = self._window[block_start:]
                        mem[first:] = self._window[:block_end]

                    flt.init_r[6] = self._written & _M32

                    if flt.prg_type != V3FilterType.VMSF_NONE:
                        out_mem = execute_v3_filter(flt.prg_type, mem, block_length, flt.init_r)
                    else:
                        out_mem = mem

                    self._prgstack[i] = None

                    while i + 1 < len(self._prgstack):
                        nf = self._prgstack[i + 1]
                        if nf is None or nf.block_start != block_start or nf.block_length != len(out_mem) or nf.next_window:
                            break
                        nf.init_r[6] = self._written & _M32
                        if nf.prg_type != V3FilterType.VMSF_NONE:
                            out_mem = execute_v3_filter(nf.prg_type, out_mem, len(out_mem), nf.init_r)
                        i += 1
                        self._prgstack[i] = None

                    self._write_data(out_mem)
                    written_border = block_end
                    write_size = (self._unp_ptr - written_border) & mask
                else:
                    for j in range(i, len(self._prgstack)):
                        f2 = self._prgstack[j]
                        if f2 is not None and f2.next_window:
                            f2.next_window = False
                    self._wr_ptr = written_border
                    return

        self._write_area(written_border, self._unp_ptr)
        self._wr_ptr = self._unp_ptr

    def _read_end_of_block(self) -> bool:
        bit_field = self._inp.getbits()
        if bit_field & 0x8000:
            new_table = True
            new_file = False
            self._inp.addbits(1)
        else:
            new_file = True
            new_table = bool(bit_field & 0x4000)
            self._inp.addbits(2)

        self._tables_read = not new_table
        if new_file:
            return False
        return self._read_tables()

    def _read_vm_code(self) -> bool:
        inp = self._inp
        first_byte = inp.getbits() >> 8
        inp.addbits(8)
        length = (first_byte & 7) + 1
        if length == 7:
            length = (inp.getbits() >> 8) + 7
            inp.addbits(8)
        elif length == 8:
            length = inp.getbits()
            inp.addbits(16)
        if length == 0:
            return False

        vm_code = bytearray(length)
        for ii in range(length):
            vm_code[ii] = (inp.getbits() >> 8) & 0xFF
            inp.addbits(8)

        return self._add_vm_code(first_byte, vm_code)

    def _read_vm_code_ppm(self) -> bool:
        first_byte = self._ppm.decode_char()
        if first_byte < 0:
            return False
        length = (first_byte & 7) + 1
        if length == 7:
            b1 = self._ppm.decode_char()
            if b1 < 0:
                return False
            length = b1 + 7
        elif length == 8:
            b1 = self._ppm.decode_char()
            if b1 < 0:
                return False
            b2 = self._ppm.decode_char()
            if b2 < 0:
                return False
            length = b1 * 256 + b2
        if length == 0:
            return False

        vm_code = bytearray(length)
        for ii in range(length):
            ch = self._ppm.decode_char()
            if ch < 0:
                return False
            vm_code[ii] = ch & 0xFF

        return self._add_vm_code(first_byte, vm_code)

    def _add_vm_code(self, first_byte: int, code: bytearray) -> bool:
        vm_inp = BitInput(code)

        if first_byte & 0x80:
            filt_pos = vm_read_data(vm_inp)
            if filt_pos == 0:
                self._init_filters(False)
                filt_pos = 0
            else:
                filt_pos -= 1
        else:
            filt_pos = self._last_filter

        if filt_pos > len(self._filters) or filt_pos > len(self._old_filter_lengths):
            return False

        self._last_filter = filt_pos
        new_filter = (filt_pos == len(self._filters))

        stack_filter = _UnpackFilter30()

        if new_filter:
            if filt_pos > MAX3_UNPACK_FILTERS:
                return False
            parent = _UnpackFilter30()
            self._filters.append(parent)
            stack_filter.parent_filter = len(self._filters) - 1
            self._old_filter_lengths.append(0)
        else:
            stack_filter.parent_filter = filt_pos

        empty_count = sum(1 for x in self._prgstack if x is None)
        self._prgstack = [x for x in self._prgstack if x is not None]
        if not empty_count:
            if len(self._prgstack) > MAX3_UNPACK_FILTERS:
                return False
        self._prgstack.append(stack_filter)

        block_start = vm_read_data(vm_inp)
        if first_byte & 0x40:
            block_start += 258
        stack_filter.block_start = (block_start + self._unp_ptr) & self._win_mask

        if first_byte & 0x20:
            stack_filter.block_length = vm_read_data(vm_inp)
            if filt_pos < len(self._old_filter_lengths):
                self._old_filter_lengths[filt_pos] = stack_filter.block_length
        else:
            stack_filter.block_length = self._old_filter_lengths[filt_pos] if filt_pos < len(self._old_filter_lengths) else 0

        stack_filter.next_window = (self._wr_ptr != self._unp_ptr
            and ((self._wr_ptr - self._unp_ptr) & self._win_mask) <= block_start)

        stack_filter.init_r = [0] * 8
        stack_filter.init_r[4] = stack_filter.block_length

        if first_byte & 0x10:
            init_mask = vm_inp.getbits() >> 9
            vm_inp.addbits(7)
            for ii in range(7):
                if init_mask & (1 << ii):
                    stack_filter.init_r[ii] = vm_read_data(vm_inp)

        if new_filter:
            vm_code_size = vm_read_data(vm_inp)
            if vm_code_size >= 0x10000 or vm_code_size == 0:
                return False
            if vm_inp.in_addr + vm_code_size > len(vm_inp.buf):
                return False
            vm_code_data = bytearray(vm_code_size)
            for ii in range(vm_code_size):
                vm_code_data[ii] = (vm_inp.getbits() >> 8) & 0xFF
                vm_inp.addbits(8)
            code_crc = zlib.crc32(vm_code_data) & 0xFFFFFFFF
            parent = self._filters[filt_pos]
            parent.prg_type = identify_v3_filter(code_crc)

        stack_filter.prg_type = self._filters[stack_filter.parent_filter].prg_type
        return True

    def _init_filters(self, solid: bool):
        if not solid:
            self._old_filter_lengths.clear()
            self._last_filter = 0
            self._filters.clear()
        self._prgstack.clear()

    def _read_tables(self) -> bool:
        inp = self._inp
        inp.addbits((8 - inp.in_bit) & 7)

        bit_field = inp.getbits()
        if bit_field & 0x8000:
            self._block_type = BLOCK_PPM
            esc_ref = [self._ppm_esc_char]
            result = self._ppm.decode_init(self._get_char, esc_ref)
            self._ppm_esc_char = esc_ref[0]
            return result

        self._block_type = BLOCK_LZ
        self._prev_low_dist = 0
        self._low_dist_rep_count = 0

        if not (bit_field & 0x4000):
            self._unp_old_table = bytearray(HUFF_TABLE_SIZE30)
        inp.addbits(2)

        bit_length = bytearray(BC30)
        i = 0
        while i < BC30:
            length = (inp.getbits() >> 12) & 0xF
            inp.addbits(4)
            if length == 15:
                zero_count = (inp.getbits() >> 12) & 0xF
                inp.addbits(4)
                if zero_count == 0:
                    bit_length[i] = 15
                else:
                    zero_count += 2
                    while zero_count > 0 and i < BC30:
                        bit_length[i] = 0
                        i += 1
                        zero_count -= 1
                    continue
            else:
                bit_length[i] = length
            i += 1

        make_decode_tables(bit_length, self._block_tables.BD, BC30)

        table = bytearray(HUFF_TABLE_SIZE30)
        i = 0
        while i < HUFF_TABLE_SIZE30:
            number = decode_number(inp, self._block_tables.BD)
            if number < 16:
                table[i] = (number + self._unp_old_table[i]) & 0xF
                i += 1
            elif number < 18:
                if number == 16:
                    n = ((inp.getbits() >> 13) & 7) + 3
                    inp.addbits(3)
                else:
                    n = ((inp.getbits() >> 9) & 0x7F) + 11
                    inp.addbits(7)
                if i == 0:
                    return False
                while n > 0 and i < HUFF_TABLE_SIZE30:
                    table[i] = table[i - 1]
                    i += 1
                    n -= 1
            else:
                if number == 18:
                    n = ((inp.getbits() >> 13) & 7) + 3
                    inp.addbits(3)
                else:
                    n = ((inp.getbits() >> 9) & 0x7F) + 11
                    inp.addbits(7)
                while n > 0 and i < HUFF_TABLE_SIZE30:
                    table[i] = 0
                    i += 1
                    n -= 1

        self._tables_read = True
        make_decode_tables(table, self._block_tables.LD, NC30)
        off = NC30
        make_decode_tables(table[off:], self._block_tables.DD, DC30)
        off += DC30
        make_decode_tables(table[off:], self._block_tables.LDD, LDC30)
        off += LDC30
        make_decode_tables(table[off:], self._block_tables.RD, RC30)
        self._unp_old_table[:] = table
        return True

    def init_solid(self, data: bytes | memoryview, dest_size: int):
        """
        Reinitialize for the next file in a solid archive chain.
        """
        self._inp = BitInput(data)
        self._dest_size = dest_size
        self._output = bytearray()
        self._written = 0
        self._solid = True

    def decompress(self) -> bytearray:
        """
        Run the RAR3 decompression and return the extracted data.
        """
        inp = self._inp
        mask = self._win_mask
        win = self._window

        if not self._solid:
            self._tables_read = False
            self._unp_old_table = bytearray(HUFF_TABLE_SIZE30)
            self._ppm_esc_char = 2
            self._block_type = BLOCK_LZ
            self._init_filters(False)

        if not self._read_tables():
            return self._output

        tbl = self._block_tables
        inp_len = len(inp.buf)

        while True:
            self._unp_ptr &= mask

            if inp.in_addr >= inp_len:
                break

            if ((self._wr_ptr - self._unp_ptr) & mask) < 260 and self._wr_ptr != self._unp_ptr:
                self._write_buf()
                if self._written > self._dest_size:
                    return self._output

            if self._block_type == BLOCK_PPM:
                ch = self._ppm.decode_char()
                if ch < 0:
                    self._ppm.cleanup()
                    self._block_type = BLOCK_LZ
                    break

                if ch == self._ppm_esc_char:
                    next_ch = self._ppm.decode_char()
                    if next_ch < 0:
                        break
                    if next_ch == 0:
                        if not self._read_tables():
                            break
                        continue
                    if next_ch == 2:
                        break
                    if next_ch == 3:
                        if not self._read_vm_code_ppm():
                            break
                        continue
                    if next_ch == 4:
                        distance = 0
                        failed = False
                        length = 0
                        for ii in range(4):
                            c = self._ppm.decode_char()
                            if c < 0:
                                failed = True
                                break
                            if ii == 3:
                                length = c & 0xFF
                            else:
                                distance = (distance << 8) + (c & 0xFF)
                        if failed:
                            break
                        self._copy_string(length + 32, distance + 2)
                        continue
                    if next_ch == 5:
                        ll = self._ppm.decode_char()
                        if ll < 0:
                            break
                        self._copy_string(ll + 4, 1)
                        continue

                win[self._unp_ptr] = ch & 0xFF
                self._unp_ptr = (self._unp_ptr + 1) & mask
                continue

            number = decode_number(inp, tbl.LD)

            if number < 256:
                win[self._unp_ptr] = number & 0xFF
                self._unp_ptr = (self._unp_ptr + 1) & mask
                continue

            if number >= 271:
                num = number - 271
                length = _LDecode[num] + 3
                bits = _LBits[num]
                if bits > 0:
                    length += inp.getbits() >> (16 - bits)
                    inp.addbits(bits)

                dist_number = decode_number(inp, tbl.DD)
                distance = _DDecode[dist_number] + 1
                d_bits = _DBits[dist_number]

                if d_bits > 0:
                    if dist_number > 9:
                        if d_bits > 4:
                            distance += (inp.getbits() >> (20 - d_bits)) << 4
                            inp.addbits(d_bits - 4)
                        if self._low_dist_rep_count > 0:
                            self._low_dist_rep_count -= 1
                            distance += self._prev_low_dist
                        else:
                            low_dist = decode_number(inp, tbl.LDD)
                            if low_dist == 16:
                                self._low_dist_rep_count = LOW_DIST_REP_COUNT - 1
                                distance += self._prev_low_dist
                            else:
                                distance += low_dist
                                self._prev_low_dist = low_dist
                    else:
                        distance += inp.getbits() >> (16 - d_bits)
                        inp.addbits(d_bits)

                if distance >= 0x2000:
                    length += 1
                    if distance >= 0x40000:
                        length += 1

                self._insert_old_dist(distance)
                self._last_length = length
                self._copy_string(length, distance)
                continue

            if number == 256:
                if not self._read_end_of_block():
                    break
                continue

            if number == 257:
                if not self._read_vm_code():
                    break
                continue

            if number == 258:
                if self._last_length != 0:
                    self._copy_string(self._last_length, self._old_dist[0])
                continue

            if number < 263:
                dist_num = number - 259
                distance = self._old_dist[dist_num]
                for idx in range(dist_num, 0, -1):
                    self._old_dist[idx] = self._old_dist[idx - 1]
                self._old_dist[0] = distance

                length_number = decode_number(inp, tbl.RD)
                length = _LDecode[length_number] + 2
                bits = _LBits[length_number]
                if bits > 0:
                    length += inp.getbits() >> (16 - bits)
                    inp.addbits(bits)
                self._last_length = length
                self._copy_string(length, distance)
                continue

            if number < 272:
                num = number - 263
                distance = _SDDecode[num] + 1
                bits = _SDBits[num]
                if bits > 0:
                    distance += inp.getbits() >> (16 - bits)
                    inp.addbits(bits)
                self._insert_old_dist(distance)
                self._last_length = 2
                self._copy_string(2, distance)
                continue

        self._write_buf()
        return self._output


@dataclass
class _BlockTables30:
    LD: DecodeTable = field(default_factory=DecodeTable)
    DD: DecodeTable = field(default_factory=DecodeTable)
    LDD: DecodeTable = field(default_factory=DecodeTable)
    RD: DecodeTable = field(default_factory=DecodeTable)
    BD: DecodeTable = field(default_factory=DecodeTable)
