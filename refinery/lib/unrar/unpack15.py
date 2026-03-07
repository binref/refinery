"""
RAR 1.5 decompression algorithm.
"""
from __future__ import annotations

from refinery.lib.unrar.reader import BitInput
from refinery.lib.unrar.unpack import RarUnpacker

_DecL1 = [0x8000, 0xA000, 0xC000, 0xD000, 0xE000, 0xEA00, 0xEE00, 0xF000, 0xF200, 0xF200, 0xFFFF]
_PosL1 = [0, 0, 0, 2, 3, 5, 7, 11, 16, 20, 24, 32, 32]
_STARTL1 = 2

_DecL2 = [0xA000, 0xC000, 0xD000, 0xE000, 0xEA00, 0xEE00, 0xF000, 0xF200, 0xF240, 0xFFFF]
_PosL2 = [0, 0, 0, 0, 5, 7, 9, 13, 18, 22, 26, 34, 36]
_STARTL2 = 3

_DecHf0 = [0x8000, 0xC000, 0xE000, 0xF200, 0xF200, 0xF200, 0xF200, 0xF200, 0xFFFF]
_PosHf0 = [0, 0, 0, 0, 0, 8, 16, 24, 33, 33, 33, 33, 33]
_STARTHF0 = 4

_DecHf1 = [0x2000, 0xC000, 0xE000, 0xF000, 0xF200, 0xF200, 0xF7E0, 0xFFFF]
_PosHf1 = [0, 0, 0, 0, 0, 0, 4, 44, 60, 76, 80, 80, 127]
_STARTHF1 = 5

_DecHf2 = [0x1000, 0x2400, 0x8000, 0xC000, 0xFA00, 0xFFFF, 0xFFFF, 0xFFFF]
_PosHf2 = [0, 0, 0, 0, 0, 0, 2, 7, 53, 117, 233, 0, 0]
_STARTHF2 = 5

_DecHf3 = [0x800, 0x2400, 0xEE00, 0xFE80, 0xFFFF, 0xFFFF, 0xFFFF]
_PosHf3 = [0, 0, 0, 0, 0, 0, 0, 2, 16, 218, 251, 0, 0]
_STARTHF3 = 6

_DecHf4 = [0xFF00, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF]
_PosHf4 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0]
_STARTHF4 = 8


def _decode_num(
    inp: BitInput,
    num: int,
    start_pos: int,
    dec_tab: list[int],
    pos_tab: list[int],
) -> int:
    """
    Decode a variable-length number using adaptive Huffman tables.
    """
    num &= 0xFFF0
    i = 0
    while dec_tab[i] <= num:
        start_pos += 1
        i += 1
    inp.addbits(start_pos)
    prev = dec_tab[i - 1] if i > 0 else 0
    return ((num - prev) >> (16 - start_pos)) + pos_tab[start_pos]


def _corr_huff(char_set: list[int], num_to_place: list[int]):
    """
    Correct Huffman table after overflow.
    """
    idx = 0
    for i in range(7, -1, -1):
        for j in range(32):
            char_set[idx] = (char_set[idx] & ~0xFF) | i
            idx += 1
    for i in range(256):
        num_to_place[i] = 0
    for i in range(6, -1, -1):
        num_to_place[i] = (7 - i) * 32


class Unpack15(RarUnpacker):
    """
    RAR 1.5 decompression engine.
    """

    def __init__(
        self,
        data: bytes | memoryview,
        unp_size: int,
        solid: bool = False,
    ):
        self._inp = BitInput(data)
        self._dest_size = unp_size
        self._orig_size = unp_size
        self._win_size = 0x10000
        self._win_mask = self._win_size - 1
        self._window = bytearray(self._win_size)
        self._solid = solid
        self._old_dist = [0, 0, 0, 0]
        self._old_dist_ptr = 0
        self._last_dist = 0
        self._last_length = 0
        self._unp_ptr = 0
        self._wr_ptr = 0
        self._written = 0
        self._output = bytearray()
        self._ch_set = [0] * 256
        self._ch_set_a = [0] * 256
        self._ch_set_b = [0] * 256
        self._ch_set_c = [0] * 256
        self._n_to_pl = [0] * 256
        self._n_to_pl_b = [0] * 256
        self._n_to_pl_c = [0] * 256
        self._avr_plc = 0
        self._avr_plc_b = 0
        self._avr_ln1 = 0
        self._avr_ln2 = 0
        self._avr_ln3 = 0
        self._nhfb = 0
        self._nlzb = 0
        self._max_dist3 = 0
        self._num_huf = 0
        self._st_mode = 0
        self._lcount = 0
        self._flags_cnt = 0
        self._flag_buf = 0
        self._buf60 = 0

    def _init_data(self):
        """
        Initialize state for non-solid decompression.
        """
        self._avr_plc_b = 0
        self._avr_ln1 = 0
        self._avr_ln2 = 0
        self._avr_ln3 = 0
        self._num_huf = 0
        self._buf60 = 0
        self._avr_plc = 0x3500
        self._max_dist3 = 0x2001
        self._nhfb = 0x80
        self._nlzb = 0x80
        self._flags_cnt = 0
        self._flag_buf = 0
        self._st_mode = 0
        self._lcount = 0

    def _init_huff(self):
        """
        Initialize Huffman character sets.
        """
        for i in range(256):
            self._ch_set[i] = i << 8
            self._ch_set_b[i] = i << 8
            self._ch_set_a[i] = i
            self._ch_set_c[i] = ((~i + 1) & 0xFF) << 8
        self._n_to_pl = [0] * 256
        self._n_to_pl_b = [0] * 256
        self._n_to_pl_c = [0] * 256
        _corr_huff(self._ch_set_b, self._n_to_pl_b)

    def _copy_string(self, distance: int, length: int):
        mask = self._win_mask
        win = self._window
        while length > 0:
            win[self._unp_ptr] = win[(self._unp_ptr - distance) & mask]
            self._unp_ptr = (self._unp_ptr + 1) & mask
            length -= 1

    def _write_data(self, data: memoryview | bytes | bytearray):
        remaining = self._orig_size - self._written
        if remaining <= 0:
            return
        write_size = min(len(data), remaining)
        self._output.extend(data[:write_size])
        self._written += write_size

    def _get_flags_buf(self):
        """
        Read next flags byte from the encoded stream.
        """
        inp = self._inp
        flags_place = _decode_num(inp, inp.getbits(), _STARTHF2, _DecHf2, _PosHf2)
        if (flags_place & 0xFF) >= 256:
            return

        flags_place &= 0xFF
        while True:
            flags = self._ch_set_c[flags_place]
            self._flag_buf = (flags >> 8) & 0xFF
            new_flags_place = self._n_to_pl_c[flags & 0xFF]
            self._n_to_pl_c[flags & 0xFF] += 1
            flags += 1
            if (flags & 0xFF) != 0:
                break
            _corr_huff(self._ch_set_c, self._n_to_pl_c)

        self._ch_set_c[flags_place] = self._ch_set_c[new_flags_place]
        self._ch_set_c[new_flags_place] = flags

    def _short_lz(self):
        """
        Handle short LZ match.
        """
        short_len1 = [1, 3, 4, 4, 5, 6, 7, 8, 8, 4, 4, 5, 6, 6, 4, 0]
        short_xor1 = [0, 0xA0, 0xD0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE,
                      0xFF, 0xC0, 0x80, 0x90, 0x98, 0x9C, 0xB0]
        short_len2 = [2, 3, 3, 3, 4, 4, 5, 6, 6, 4, 4, 5, 6, 6, 4, 0]
        short_xor2 = [0, 0x40, 0x60, 0xA0, 0xD0, 0xE0, 0xF0, 0xF8,
                      0xFC, 0xC0, 0x80, 0x90, 0x98, 0x9C, 0xB0]

        inp = self._inp
        self._num_huf = 0

        bit_field = inp.getbits()
        if self._lcount == 2:
            inp.addbits(1)
            if bit_field >= 0x8000:
                self._copy_string(self._last_dist, self._last_length)
                self._dest_size -= self._last_length
                return
            bit_field <<= 1
            self._lcount = 0

        bit_field >>= 8
        bit_field &= 0xFF

        def get_short_len1(pos):
            return self._buf60 + 3 if pos == 1 else short_len1[pos]

        def get_short_len2(pos):
            return self._buf60 + 3 if pos == 3 else short_len2[pos]

        if self._avr_ln1 < 37:
            length = 0
            while True:
                slen = get_short_len1(length)
                mask = (~(0xFF >> slen)) & 0xFF if slen < 8 else 0xFF
                if (bit_field ^ short_xor1[length]) & mask == 0:
                    break
                length += 1
                if length >= 15:
                    break
            inp.addbits(get_short_len1(length))
        else:
            length = 0
            while True:
                slen = get_short_len2(length)
                mask = (~(0xFF >> slen)) & 0xFF if slen < 8 else 0xFF
                if (bit_field ^ short_xor2[length]) & mask == 0:
                    break
                length += 1
                if length >= 15:
                    break
            inp.addbits(get_short_len2(length))

        if length >= 9:
            if length == 9:
                self._lcount += 1
                self._copy_string(self._last_dist, self._last_length)
                self._dest_size -= self._last_length
                return

            if length == 14:
                self._lcount = 0
                length = _decode_num(inp, inp.getbits(), _STARTL2, _DecL2, _PosL2) + 5
                distance = (inp.getbits() >> 1) | 0x8000
                inp.addbits(15)
                self._last_length = length
                self._last_dist = distance
                self._copy_string(distance, length)
                self._dest_size -= length
                return

            self._lcount = 0
            save_length = length
            distance = self._old_dist[(self._old_dist_ptr - (length - 9)) & 3]
            length = _decode_num(inp, inp.getbits(), _STARTL1, _DecL1, _PosL1) + 2
            if length == 0x101 and save_length == 10:
                self._buf60 ^= 1
                return
            if distance > 256:
                length += 1
            if distance >= self._max_dist3:
                length += 1

            self._old_dist[self._old_dist_ptr] = distance
            self._old_dist_ptr = (self._old_dist_ptr + 1) & 3
            self._last_length = length
            self._last_dist = distance
            self._copy_string(distance, length)
            self._dest_size -= length
            return

        self._lcount = 0
        self._avr_ln1 += length
        self._avr_ln1 -= self._avr_ln1 >> 4

        distance_place = _decode_num(inp, inp.getbits(), _STARTHF2, _DecHf2, _PosHf2) & 0xFF
        distance = self._ch_set_a[distance_place]
        if distance_place > 0:
            last_distance = self._ch_set_a[distance_place - 1]
            self._ch_set_a[distance_place] = last_distance
            self._ch_set_a[distance_place - 1] = distance

        length += 2
        distance += 1
        self._old_dist[self._old_dist_ptr] = distance
        self._old_dist_ptr = (self._old_dist_ptr + 1) & 3
        self._last_length = length
        self._last_dist = distance
        self._copy_string(distance, length)
        self._dest_size -= length

    def _long_lz(self):
        """
        Handle long LZ match.
        """
        inp = self._inp
        self._num_huf = 0
        self._nlzb += 16
        if self._nlzb > 0xFF:
            self._nlzb = 0x90
            self._nhfb >>= 1

        old_avr2 = self._avr_ln2

        bit_field = inp.getbits()
        if self._avr_ln2 >= 122:
            length = _decode_num(inp, bit_field, _STARTL2, _DecL2, _PosL2)
        elif self._avr_ln2 >= 64:
            length = _decode_num(inp, bit_field, _STARTL1, _DecL1, _PosL1)
        elif bit_field < 0x100:
            length = bit_field
            inp.addbits(16)
        else:
            length = 0
            while ((bit_field << length) & 0x8000) == 0:
                length += 1
            inp.addbits(length + 1)

        self._avr_ln2 += length
        self._avr_ln2 -= self._avr_ln2 >> 5

        bit_field = inp.getbits()
        if self._avr_plc_b > 0x28FF:
            distance_place = _decode_num(inp, bit_field, _STARTHF2, _DecHf2, _PosHf2)
        elif self._avr_plc_b > 0x6FF:
            distance_place = _decode_num(inp, bit_field, _STARTHF1, _DecHf1, _PosHf1)
        else:
            distance_place = _decode_num(inp, bit_field, _STARTHF0, _DecHf0, _PosHf0)

        self._avr_plc_b += distance_place
        self._avr_plc_b -= self._avr_plc_b >> 8

        while True:
            distance = self._ch_set_b[distance_place & 0xFF]
            new_distance_place = self._n_to_pl_b[distance & 0xFF]
            self._n_to_pl_b[distance & 0xFF] += 1
            distance += 1
            if not (distance & 0xFF) == 0:
                break
            _corr_huff(self._ch_set_b, self._n_to_pl_b)

        self._ch_set_b[distance_place & 0xFF] = self._ch_set_b[new_distance_place]
        self._ch_set_b[new_distance_place] = distance

        distance = ((distance & 0xFF00) | ((inp.getbits() >> 8) & 0xFF)) >> 1
        inp.addbits(7)

        old_avr3 = self._avr_ln3
        if length != 1 and length != 4:
            if length == 0 and distance <= self._max_dist3:
                self._avr_ln3 += 1
                self._avr_ln3 -= self._avr_ln3 >> 8
            elif self._avr_ln3 > 0:
                self._avr_ln3 -= 1

        length += 3
        if distance >= self._max_dist3:
            length += 1
        if distance <= 256:
            length += 8
        if (old_avr3 > 0xB0
                or (self._avr_plc >= 0x2A00 and old_avr2 < 0x40)):
            self._max_dist3 = 0x7F00
        else:
            self._max_dist3 = 0x2001

        self._old_dist[self._old_dist_ptr] = distance
        self._old_dist_ptr = (self._old_dist_ptr + 1) & 3
        self._last_length = length
        self._last_dist = distance
        self._copy_string(distance, length)
        self._dest_size -= length

    def _huff_decode(self):
        """
        Huffman literal / special code decode.
        """
        inp = self._inp
        bit_field = inp.getbits()

        if self._avr_plc > 0x75FF:
            byte_place = _decode_num(inp, bit_field, _STARTHF4, _DecHf4, _PosHf4)
        elif self._avr_plc > 0x5DFF:
            byte_place = _decode_num(inp, bit_field, _STARTHF3, _DecHf3, _PosHf3)
        elif self._avr_plc > 0x35FF:
            byte_place = _decode_num(inp, bit_field, _STARTHF2, _DecHf2, _PosHf2)
        elif self._avr_plc > 0x0DFF:
            byte_place = _decode_num(inp, bit_field, _STARTHF1, _DecHf1, _PosHf1)
        else:
            byte_place = _decode_num(inp, bit_field, _STARTHF0, _DecHf0, _PosHf0)

        byte_place &= 0xFF

        if self._st_mode:
            if byte_place == 0 and bit_field > 0xFFF:
                byte_place = 0x100
            byte_place -= 1
            if byte_place == -1:
                bit_field = inp.getbits()
                inp.addbits(1)
                if bit_field & 0x8000:
                    self._num_huf = 0
                    self._st_mode = 0
                    return
                else:
                    length = 4 if (bit_field & 0x4000) else 3
                    inp.addbits(1)
                    distance = _decode_num(inp, inp.getbits(), _STARTHF2, _DecHf2, _PosHf2)
                    distance = (distance << 5) | (inp.getbits() >> 11)
                    inp.addbits(5)
                    self._copy_string(distance, length)
                    self._dest_size -= length
                    return
        else:
            if self._num_huf >= 16 and self._flags_cnt == 0:
                self._st_mode = 1
            self._num_huf += 1

        self._avr_plc += byte_place
        self._avr_plc -= self._avr_plc >> 8
        self._nhfb += 16
        if self._nhfb > 0xFF:
            self._nhfb = 0x90
            self._nlzb >>= 1

        self._window[self._unp_ptr] = (self._ch_set[byte_place] >> 8) & 0xFF
        self._unp_ptr = (self._unp_ptr + 1) & self._win_mask
        self._dest_size -= 1

        while True:
            cur_byte = self._ch_set[byte_place]
            new_byte_place = self._n_to_pl[cur_byte & 0xFF]
            self._n_to_pl[cur_byte & 0xFF] += 1
            cur_byte += 1
            if (cur_byte & 0xFF) > 0xA1:
                _corr_huff(self._ch_set, self._n_to_pl)
            else:
                break

        self._ch_set[byte_place] = self._ch_set[new_byte_place]
        self._ch_set[new_byte_place] = cur_byte

    def init_solid(self, data: bytes | memoryview, dest_size: int):
        """
        Reinitialize for the next file in a solid archive chain.
        """
        super().init_solid(data, dest_size)
        self._orig_size = dest_size

    def decompress(self) -> bytearray:
        """
        Run the RAR 1.5 decompression and return the extracted data.
        """
        if not self._solid:
            self._init_data()
            self._init_huff()
            self._unp_ptr = 0
        else:
            self._unp_ptr = self._wr_ptr

        self._flags_cnt = 0
        self._flag_buf = 0
        self._st_mode = 0
        self._lcount = 0

        self._dest_size -= 1
        if self._dest_size >= 0:
            self._get_flags_buf()
            self._flags_cnt = 8

        while self._dest_size >= 0:
            self._unp_ptr &= self._win_mask

            if ((self._wr_ptr - self._unp_ptr) & self._win_mask) < 270 and self._wr_ptr != self._unp_ptr:
                self._write_buf()

            if self._st_mode:
                self._huff_decode()
                continue

            self._flags_cnt -= 1
            if self._flags_cnt < 0:
                self._get_flags_buf()
                self._flags_cnt = 7

            if self._flag_buf & 0x80:
                self._flag_buf = (self._flag_buf << 1) & 0xFF
                if self._nlzb > self._nhfb:
                    self._long_lz()
                else:
                    self._huff_decode()
            else:
                self._flag_buf = (self._flag_buf << 1) & 0xFF
                self._flags_cnt -= 1
                if self._flags_cnt < 0:
                    self._get_flags_buf()
                    self._flags_cnt = 7
                if self._flag_buf & 0x80:
                    self._flag_buf = (self._flag_buf << 1) & 0xFF
                    if self._nlzb > self._nhfb:
                        self._huff_decode()
                    else:
                        self._long_lz()
                else:
                    self._flag_buf = (self._flag_buf << 1) & 0xFF
                    self._short_lz()

        self._write_buf()
        return self._output
