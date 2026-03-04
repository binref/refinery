"""
RAR 2.0 decompression algorithm.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from refinery.lib.unrar.reader import BitInput
from refinery.lib.unrar.unpack50 import DecodeTable, decode_number, make_decode_tables

NC20 = 298
DC20 = 48
RC20 = 28
BC20 = 19
MC20 = 257


_LDecode = [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224]
_LBits = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5]
_DDecode = [0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096,
    6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072, 196608, 262144, 327680, 393216, 458752, 524288,
    589824, 655360, 720896, 786432, 851968, 917504, 983040]
_DBits = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14, 15,
    15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16]
_SDDecode = [0, 4, 8, 16, 32, 64, 128, 192]
_SDBits = [2, 2, 3, 4, 5, 6, 6, 6]


@dataclass
class _AudioVariables:
    K: list[int] = field(default_factory=lambda: [0] * 5)
    D1: int = 0
    D2: int = 0
    D3: int = 0
    D4: int = 0
    last_delta: int = 0
    dif: list[int] = field(default_factory=lambda: [0] * 11)
    byte_count: int = 0
    last_char: int = 0


@dataclass
class _BlockTables20:
    LD: DecodeTable = field(default_factory=DecodeTable)
    DD: DecodeTable = field(default_factory=DecodeTable)
    RD: DecodeTable = field(default_factory=DecodeTable)
    BD: DecodeTable = field(default_factory=DecodeTable)


class Unpack20:
    """
    RAR 2.0 decompression engine.
    """

    def __init__(
        self,
        data: bytes | memoryview,
        unp_size: int,
        solid: bool = False,
    ):
        self._inp = BitInput(data)
        self._dest_size = unp_size
        self._win_size = 0x100000
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
        self._tables_read = False
        self._block_tables = _BlockTables20()
        self._audio_block = False
        self._channels = 1
        self._cur_channel = 0
        self._channel_delta = 0
        self._aud_v = [_AudioVariables() for _ in range(4)]
        self._old_table = bytearray(MC20 * 4)
        self._md = [DecodeTable() for _ in range(4)]

    def _copy_string(self, length: int, distance: int):
        self._last_dist = distance
        self._old_dist[self._old_dist_ptr] = distance
        self._old_dist_ptr = (self._old_dist_ptr + 1) & 3
        self._last_length = length
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

    def _write_buf(self):
        win = self._window
        if self._unp_ptr < self._wr_ptr:
            self._write_data(win[self._wr_ptr:self._win_size])
            self._write_data(win[:self._unp_ptr])
        elif self._unp_ptr > self._wr_ptr:
            self._write_data(win[self._wr_ptr:self._unp_ptr])
        self._wr_ptr = self._unp_ptr

    def _decode_audio(self, delta: int) -> int:
        """
        Decode audio data byte.
        """
        v = self._aud_v[self._cur_channel]
        v.byte_count += 1
        v.D4 = v.D3
        v.D3 = v.D2
        v.D2 = v.last_delta - v.D1
        v.D1 = v.last_delta

        K1, K2, K3, K4, K5 = k = v.K
        pch = (8 * v.last_char + K1 * v.D1 + K2 * v.D2 + K3 * v.D3 + K4 * v.D4 + K5 * self._channel_delta)
        pch = (pch >> 3) & 0xFF

        ch = (pch - delta) & 0xFF

        d = delta if delta < 128 else delta - 256
        d = (d & 0xFFFFFFFF) << 3 if d >= 0 else (((d + 0x100000000) & 0xFFFFFFFF) << 3)
        d_s = d if d < 0x80000000 else d - 0x100000000

        v.dif[0] += abs(d_s)
        v.dif[1] += abs(d_s - v.D1)
        v.dif[2] += abs(d_s + v.D1)
        v.dif[3] += abs(d_s - v.D2)
        v.dif[4] += abs(d_s + v.D2)
        v.dif[5] += abs(d_s - v.D3)
        v.dif[6] += abs(d_s + v.D3)
        v.dif[7] += abs(d_s - v.D4)
        v.dif[8] += abs(d_s + v.D4)
        v.dif[9] += abs(d_s - self._channel_delta)
        v.dif[10] += abs(d_s + self._channel_delta)

        diff = (ch - v.last_char) & 0xFF
        v.last_delta = diff if diff < 128 else diff - 256
        self._channel_delta = v.last_delta
        v.last_char = ch

        if (v.byte_count & 0x1F) == 0:
            min_dif = v.dif[0]
            num_min_dif = 0
            v.dif[0] = 0
            for i in range(1, 11):
                if v.dif[i] < min_dif:
                    min_dif = v.dif[i]
                    num_min_dif = i
                v.dif[i] = 0
            if num_min_dif in range(10):
                direction = (num_min_dif + 1) % -2
                index = num_min_dif // 2
                val = k[index]
                if direction < 0 and val >= -16:
                    k[index] = val - 1
                elif direction > 0 and val < 16:
                    k[index] = val + 1

        return ch & 0xFF

    def _read_tables(self) -> bool:
        """
        Read Huffman tables for RAR 2.0 block.
        """
        inp = self._inp
        bit_field = inp.getbits()
        self._audio_block = bool(bit_field & 0x8000)

        if not (bit_field & 0x4000):
            self._old_table = bytearray(MC20 * 4)
        inp.addbits(2)

        if self._audio_block:
            self._channels = ((bit_field >> 12) & 3) + 1
            if self._cur_channel >= self._channels:
                self._cur_channel = 0
            inp.addbits(2)
            table_size = MC20 * self._channels
        else:
            table_size = NC20 + DC20 + RC20

        bit_length = bytearray(BC20)
        for i in range(BC20):
            bit_length[i] = (inp.getbits() >> 12) & 0xF
            inp.addbits(4)
        make_decode_tables(bit_length, self._block_tables.BD, BC20)

        table = bytearray(table_size)
        i = 0
        while i < table_size:
            number = decode_number(inp, self._block_tables.BD)
            if number < 16:
                table[i] = (number + self._old_table[i]) & 0xF
                i += 1
            elif number == 16:
                n = ((inp.getbits() >> 14) & 3) + 3
                inp.addbits(2)
                if i == 0:
                    return False
                while n > 0 and i < table_size:
                    table[i] = table[i - 1]
                    i += 1
                    n -= 1
            else:
                if number == 17:
                    n = ((inp.getbits() >> 13) & 7) + 3
                    inp.addbits(3)
                else:
                    n = ((inp.getbits() >> 9) & 0x7F) + 11
                    inp.addbits(7)
                while n > 0 and i < table_size:
                    table[i] = 0
                    i += 1
                    n -= 1

        self._tables_read = True

        if self._audio_block:
            for ch in range(self._channels):
                make_decode_tables(table[ch * MC20:], self._md[ch], MC20)
        else:
            make_decode_tables(table, self._block_tables.LD, NC20)
            make_decode_tables(table[NC20:], self._block_tables.DD, DC20)
            make_decode_tables(table[NC20 + DC20:], self._block_tables.RD, RC20)

        self._old_table[:table_size] = table[:table_size]
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
        Run the RAR 2.0 decompression and return the extracted data.
        """
        inp = self._inp
        mask = self._win_mask
        win = self._window

        if (not self._solid or not self._tables_read) and not self._read_tables():
            return self._output

        remaining = self._dest_size
        while remaining >= 0:
            self._unp_ptr &= mask

            if ((self._wr_ptr - self._unp_ptr) & mask) < 270 and self._wr_ptr != self._unp_ptr:
                self._write_buf()

            if self._audio_block:
                audio_number = decode_number(inp, self._md[self._cur_channel])
                if audio_number == 256:
                    if not self._read_tables():
                        break
                    continue
                win[self._unp_ptr] = self._decode_audio(audio_number)
                self._unp_ptr = (self._unp_ptr + 1) & mask
                self._cur_channel = (self._cur_channel + 1) % self._channels
                remaining -= 1
                continue

            number = decode_number(inp, self._block_tables.LD)

            if number < 256:
                win[self._unp_ptr] = number & 0xFF
                self._unp_ptr = (self._unp_ptr + 1) & mask
                remaining -= 1
                continue

            if number > 269:
                idx = number - 270
                length = _LDecode[idx] + 3
                bits = _LBits[idx]
                if bits > 0:
                    length += inp.getbits() >> (16 - bits)
                    inp.addbits(bits)

                dist_number = decode_number(inp, self._block_tables.DD)
                distance = _DDecode[dist_number] + 1
                bits = _DBits[dist_number]
                if bits > 0:
                    distance += inp.getbits() >> (16 - bits)
                    inp.addbits(bits)

                if distance >= 0x2000:
                    length += 1
                    if distance >= 0x40000:
                        length += 1

                self._copy_string(length, distance)
                remaining -= length
                continue

            if number == 269:
                if not self._read_tables():
                    break
                continue

            if number == 256:
                self._copy_string(self._last_length, self._last_dist)
                remaining -= self._last_length
                continue

            if number < 261:
                distance = self._old_dist[(self._old_dist_ptr - (number - 256)) & 3]
                length_number = decode_number(inp, self._block_tables.RD)
                length = _LDecode[length_number] + 2
                bits = _LBits[length_number]
                if bits > 0:
                    length += inp.getbits() >> (16 - bits)
                    inp.addbits(bits)

                if distance >= 0x101:
                    length += 1
                    if distance >= 0x2000:
                        length += 1
                        if distance >= 0x40000:
                            length += 1

                self._copy_string(length, distance)
                remaining -= length
                continue

            if number < 270:
                idx = number - 261
                distance = _SDDecode[idx] + 1
                bits = _SDBits[idx]
                if bits > 0:
                    distance += inp.getbits() >> (16 - bits)
                    inp.addbits(bits)
                self._copy_string(2, distance)
                remaining -= 2
                continue

        self._write_buf()
        return self._output
