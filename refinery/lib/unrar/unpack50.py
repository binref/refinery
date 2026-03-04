"""
RAR 5.0 decompression algorithm.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from refinery.lib.unrar.filters import FilterType, UnpackFilter, apply_filter
from refinery.lib.unrar.reader import BitInput

NC = 306
DC = 64
LDC = 16
RC = 44
BC = 20
HUFF_TABLE_SIZE = NC + DC + RC + LDC
LARGEST_TABLE_SIZE = 306
MAX_QUICK_DECODE_BITS = 10
MAX_UNPACK_FILTERS = 8192
MAX_FILTER_BLOCK_SIZE = 0x400000
UNPACK_MAX_WRITE = 0x400000
MAX_INC_LZ_MATCH = 0x1001 + 3


@dataclass
class DecodeTable:
    max_num: int = 0
    decode_len: list[int] = field(default_factory=lambda: [0] * 16)
    decode_pos: list[int] = field(default_factory=lambda: [0] * 16)
    quick_bits: int = 0
    quick_len: bytearray = field(default_factory=lambda: bytearray(1 << MAX_QUICK_DECODE_BITS))
    quick_num: list[int] = field(default_factory=lambda: [0] * (1 << MAX_QUICK_DECODE_BITS))
    decode_num: list[int] = field(default_factory=lambda: [0] * LARGEST_TABLE_SIZE)


def make_decode_tables(length_table: bytearray, dec: DecodeTable, size: int):
    """
    Build Huffman decode tables from bit length table.
    """
    dec.max_num = size

    length_count = [0] * 16
    for i in range(size):
        length_count[length_table[i] & 0xF] += 1
    length_count[0] = 0

    for i in range(size):
        dec.decode_num[i] = 0

    dec.decode_pos[0] = 0
    dec.decode_len[0] = 0

    upper_limit = 0
    for i in range(1, 16):
        upper_limit += length_count[i]
        left_aligned = upper_limit << (16 - i)
        upper_limit *= 2
        dec.decode_len[i] = left_aligned
        dec.decode_pos[i] = dec.decode_pos[i - 1] + length_count[i - 1]

    copy_decode_pos = list(dec.decode_pos)

    for i in range(size):
        cur_bit_length = length_table[i] & 0xF
        if cur_bit_length != 0:
            last_pos = copy_decode_pos[cur_bit_length]
            if last_pos < size:
                dec.decode_num[last_pos] = i
            copy_decode_pos[cur_bit_length] += 1

    if size in (NC, 298, 299):
        dec.quick_bits = MAX_QUICK_DECODE_BITS
    else:
        dec.quick_bits = MAX_QUICK_DECODE_BITS - 3

    quick_data_size = 1 << dec.quick_bits
    cur_bit_length = 1

    for code in range(quick_data_size):
        bit_field = code << (16 - dec.quick_bits)
        while cur_bit_length < 16 and bit_field >= dec.decode_len[cur_bit_length]:
            cur_bit_length += 1
        dec.quick_len[code] = cur_bit_length

        dist = bit_field - dec.decode_len[cur_bit_length - 1]
        dist >>= (16 - cur_bit_length)
        pos = dec.decode_pos[cur_bit_length] + dist if cur_bit_length < 16 else 0
        if pos < size:
            dec.quick_num[code] = dec.decode_num[pos]
        else:
            dec.quick_num[code] = 0


def decode_number(inp: BitInput, dec: DecodeTable) -> int:
    """
    Decode a Huffman symbol.
    """
    bit_field = inp.getbits() & 0xFFFE

    if bit_field < dec.decode_len[dec.quick_bits]:
        code = bit_field >> (16 - dec.quick_bits)
        inp.addbits(dec.quick_len[code])
        return dec.quick_num[code]

    bits = 15
    for i in range(dec.quick_bits + 1, 15):
        if bit_field < dec.decode_len[i]:
            bits = i
            break

    inp.addbits(bits)
    dist = bit_field - dec.decode_len[bits - 1]
    dist >>= (16 - bits)
    pos = dec.decode_pos[bits] + dist
    if pos >= dec.max_num:
        pos = 0
    return dec.decode_num[pos]


def slot_to_length(inp: BitInput, slot: int) -> int:
    """
    Convert a length slot to actual length.
    """
    if slot < 8:
        l_bits = 0
        length = 2 + slot
    else:
        l_bits = slot // 4 - 1
        length = 2 + ((4 | (slot & 3)) << l_bits)

    if l_bits > 0:
        length += inp.getbits() >> (16 - l_bits)
        inp.addbits(l_bits)
    return length


@dataclass
class BlockHeader:
    block_size: int = -1
    block_bit_size: int = 0
    block_start: int = 0
    header_size: int = 0
    last_block: bool = False
    table_present: bool = False


@dataclass
class BlockTables:
    LD: DecodeTable = field(default_factory=DecodeTable)
    DD: DecodeTable = field(default_factory=DecodeTable)
    LDD: DecodeTable = field(default_factory=DecodeTable)
    RD: DecodeTable = field(default_factory=DecodeTable)
    BD: DecodeTable = field(default_factory=DecodeTable)


def read_block_header(inp: BitInput, header: BlockHeader) -> bool:
    """
    Read a RAR5 compression block header.
    """
    header.header_size = 0

    inp.addbits((8 - inp.in_bit) & 7)

    if inp.remaining < 7:
        return False

    block_flags = inp.getbits() >> 8
    inp.addbits(8)

    byte_count = ((block_flags >> 3) & 3) + 1
    if byte_count == 4:
        return False

    header.header_size = 2 + byte_count
    header.block_bit_size = (block_flags & 7) + 1

    saved_checksum = inp.getbits() >> 8
    inp.addbits(8)

    block_size = 0
    for i in range(byte_count):
        block_size += (inp.getbits() >> 8) << (i * 8)
        inp.addbits(8)

    header.block_size = block_size
    checksum = (0x5A ^ block_flags ^ (block_size & 0xFF) ^ ((block_size >> 8) & 0xFF) ^ ((block_size >> 16) & 0xFF)) & 0xFF
    if checksum != saved_checksum:
        return False

    header.block_start = inp.in_addr
    header.last_block = bool(block_flags & 0x40)
    header.table_present = bool(block_flags & 0x80)
    return True


def read_tables(inp: BitInput, header: BlockHeader, tables: BlockTables) -> bool:
    """
    Read Huffman tables from a block.
    """
    if not header.table_present:
        return True

    bit_length = bytearray(BC)
    i = 0
    while i < BC:
        length = (inp.getbits() >> 12) & 0xF
        inp.addbits(4)
        if length == 15:
            zero_count = (inp.getbits() >> 12) & 0xF
            inp.addbits(4)
            if zero_count == 0:
                bit_length[i] = 15
            else:
                zero_count += 2
                while zero_count > 0 and i < BC:
                    bit_length[i] = 0
                    i += 1
                    zero_count -= 1
                continue
        else:
            bit_length[i] = length
        i += 1

    make_decode_tables(bit_length, tables.BD, BC)

    table = bytearray(HUFF_TABLE_SIZE)
    i = 0
    while i < HUFF_TABLE_SIZE:
        number = decode_number(inp, tables.BD)
        if number < 16:
            table[i] = number
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
            while n > 0 and i < HUFF_TABLE_SIZE:
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
            while n > 0 and i < HUFF_TABLE_SIZE:
                table[i] = 0
                i += 1
                n -= 1

    make_decode_tables(table, tables.LD, NC)
    off = NC
    make_decode_tables(table[off:], tables.DD, DC)
    off += DC
    make_decode_tables(table[off:], tables.LDD, LDC)
    off += LDC
    make_decode_tables(table[off:], tables.RD, RC)
    return True


def read_filter_data(inp: BitInput) -> int:
    """
    Read a variable-length filter data value.
    """
    byte_count = ((inp.getbits() >> 14) & 3) + 1
    inp.addbits(2)
    data = 0
    for i in range(byte_count):
        data += ((inp.getbits() >> 8) & 0xFF) << (i * 8)
        inp.addbits(8)
    return data


def read_filter(inp: BitInput) -> UnpackFilter | None:
    """
    Read a RAR5 filter definition.
    """
    flt = UnpackFilter()
    flt.block_start = read_filter_data(inp)
    flt.block_length = read_filter_data(inp)
    if flt.block_length > MAX_FILTER_BLOCK_SIZE:
        flt.block_length = 0

    flt.type = (inp.getbits() >> 13) & 7
    inp.addbits(3)

    if flt.type == FilterType.FILTER_DELTA:
        flt.channels = ((inp.getbits() >> 11) & 0x1F) + 1
        inp.addbits(5)

    return flt


class Unpack50:
    """
    RAR 5.0 decompression engine
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
        self._filters: list[UnpackFilter] = []
        self._tables_read = False
        self._block_header = BlockHeader()
        self._block_tables = BlockTables()
        self._write_border = min(self._win_size, UNPACK_MAX_WRITE) & self._win_mask

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
        """
        Write extracted data, respecting dest_size limit.
        """
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
        """
        Apply filters and flush the write buffer.
        """
        written_border = self._wr_ptr
        mask = self._win_mask
        full_write_size = (self._unp_ptr - written_border) & mask
        write_size_left = full_write_size

        for i, flt in enumerate(self._filters):
            if flt.type == FilterType.FILTER_NONE:
                continue
            if flt.next_window:
                if ((flt.block_start - self._wr_ptr) & mask) <= full_write_size:
                    flt.next_window = False
                continue

            block_start = flt.block_start
            block_length = flt.block_length

            if ((block_start - written_border) & mask) < write_size_left:
                if written_border != block_start:
                    self._write_area(written_border, block_start)
                    written_border = block_start
                    write_size_left = (self._unp_ptr - written_border) & mask

                if block_length <= write_size_left:
                    if block_length > 0:
                        block_end = (block_start + block_length) & mask
                        mem = bytearray(block_length)
                        if block_start < block_end or block_end == 0:
                            mem[:] = self._window[block_start:block_start + block_length]
                        else:
                            first_part = self._win_size - block_start
                            mem[:first_part] = self._window[block_start:]
                            mem[first_part:] = self._window[:block_end]

                        out_mem = apply_filter(mem, flt.type, flt.channels, self._written)
                        self._filters[i].type = FilterType.FILTER_NONE

                        if out_mem is not None:
                            self._write_data(out_mem)

                        written_border = block_end
                        write_size_left = (self._unp_ptr - written_border) & mask
                else:
                    self._wr_ptr = written_border
                    for j in range(i, len(self._filters)):
                        if self._filters[j].type != FilterType.FILTER_NONE:
                            self._filters[j].next_window = False
                    self._filters = [f for f in self._filters if f.type != FilterType.FILTER_NONE]
                    self._write_border = (self._unp_ptr + min(self._win_size, UNPACK_MAX_WRITE)) & mask
                    return

        self._filters = [f for f in self._filters if f.type != FilterType.FILTER_NONE]
        self._write_area(written_border, self._unp_ptr)
        self._wr_ptr = self._unp_ptr
        self._write_border = (self._unp_ptr + min(self._win_size, UNPACK_MAX_WRITE)) & mask

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
        Run the RAR5 decompression and return the extracted data.
        """
        inp = self._inp
        mask = self._win_mask
        win = self._window

        if not read_block_header(inp, self._block_header):
            return self._output
        if not read_tables(inp, self._block_header, self._block_tables):
            return self._output
        self._tables_read = True

        hdr = self._block_header
        tbl = self._block_tables

        inp_len = len(inp.buf)

        while True:
            self._unp_ptr &= mask

            if inp.in_addr >= inp_len:
                break

            while (inp.in_addr > hdr.block_start + hdr.block_size - 1
                or (inp.in_addr == hdr.block_start + hdr.block_size - 1
                    and inp.in_bit >= hdr.block_bit_size)):
                if hdr.last_block:
                    self._write_buf()
                    return self._output
                if not read_block_header(inp, hdr) or not read_tables(inp, hdr, tbl):
                    self._write_buf()
                    return self._output

            if ((self._write_border - self._unp_ptr) & mask) < MAX_INC_LZ_MATCH and self._write_border != self._unp_ptr:
                self._write_buf()
                if self._written > self._dest_size:
                    return self._output

            main_slot = decode_number(inp, tbl.LD)

            if main_slot < 256:
                win[self._unp_ptr] = main_slot & 0xFF
                self._unp_ptr = (self._unp_ptr + 1) & mask
                continue

            if main_slot >= 262:
                length = slot_to_length(inp, main_slot - 262)

                dist_slot = decode_number(inp, tbl.DD)
                if dist_slot < 4:
                    d_bits = 0
                    distance = 1 + dist_slot
                else:
                    d_bits = dist_slot // 2 - 1
                    distance = 1 + ((2 | (dist_slot & 1)) << d_bits)

                if d_bits > 0:
                    if d_bits >= 4:
                        if d_bits > 4:
                            distance += (inp.getbits32() >> (36 - d_bits)) << 4
                            inp.addbits(d_bits - 4)
                        low_dist = decode_number(inp, tbl.LDD)
                        distance += low_dist
                    else:
                        distance += inp.getbits32() >> (32 - d_bits)
                        inp.addbits(d_bits)

                if distance > 0x100:
                    length += 1
                    if distance > 0x2000:
                        length += 1
                        if distance > 0x40000:
                            length += 1

                self._insert_old_dist(distance)
                self._last_length = length
                self._copy_string(length, distance)
                continue

            if main_slot == 256:
                flt = read_filter(inp)
                if flt is None:
                    break
                flt.next_window = (self._wr_ptr != self._unp_ptr
                    and ((self._wr_ptr - self._unp_ptr) & mask) <= flt.block_start)
                flt.block_start = (flt.block_start + self._unp_ptr) & mask
                if len(self._filters) >= MAX_UNPACK_FILTERS:
                    self._write_buf()
                    if len(self._filters) >= MAX_UNPACK_FILTERS:
                        self._filters.clear()
                self._filters.append(flt)
                continue

            if main_slot == 257:
                if self._last_length != 0:
                    self._copy_string(self._last_length, self._old_dist[0])
                continue

            if main_slot < 262:
                dist_num = main_slot - 258
                distance = self._old_dist[dist_num]
                for idx in range(dist_num, 0, -1):
                    self._old_dist[idx] = self._old_dist[idx - 1]
                self._old_dist[0] = distance

                length_slot = decode_number(inp, tbl.RD)
                length = slot_to_length(inp, length_slot)
                self._last_length = length
                self._copy_string(length, distance)
                continue

        self._write_buf()
        return self._output
