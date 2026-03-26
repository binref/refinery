# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True
"""
RAR 5.0 decompression algorithm, Cython-optimized version.
"""
cimport cython

from libc.string cimport memcpy, memset
from cpython.bytearray cimport PyByteArray_AS_STRING

from refinery.lib.unrar.filters import FilterType, UnpackFilter, apply_filter
from refinery.lib.unrar.unpack import RarUnpacker

cdef int NC = 306
cdef int DC = 64
cdef int LDC = 16
cdef int RC = 44
cdef int BC = 20
cdef int HUFF_TABLE_SIZE = NC + DC + RC + LDC
cdef int LARGEST_TABLE_SIZE = 306
cdef int MAX_QUICK_DECODE_BITS = 10
cdef int MAX_UNPACK_FILTERS = 8192
cdef int MAX_FILTER_BLOCK_SIZE = 0x400000
cdef int UNPACK_MAX_WRITE = 0x400000
cdef int MAX_INC_LZ_MATCH = 0x1001 + 3


cdef class BitInput:
    cdef:
        const unsigned char[::1] _buf
        public int in_addr
        public int in_bit
        int _buf_len

    def __init__(self, data):
        if isinstance(data, memoryview):
            self._buf = data
        else:
            self._buf = memoryview(bytes(data))
        self.in_addr = 0
        self.in_bit = 0
        self._buf_len = len(data)

    @property
    def buf(self):
        return self._buf

    @property
    def remaining(self):
        cdef int r = self._buf_len - self.in_addr
        return r if r > 0 else 0

    def init(self):
        self.in_addr = 0
        self.in_bit = 0

    cpdef int getbits(self):
        cdef int addr = self.in_addr
        cdef int bit = self.in_bit
        cdef int blen = self._buf_len
        cdef int b0, b1, b2, val
        b0 = self._buf[addr] if addr < blen else 0
        b1 = self._buf[addr + 1] if addr + 1 < blen else 0
        b2 = self._buf[addr + 2] if addr + 2 < blen else 0
        val = (b0 << 16) | (b1 << 8) | b2
        return (val >> (8 - bit)) & 0xFFFF

    cpdef unsigned int getbits32(self):
        cdef int addr = self.in_addr
        cdef int bit = self.in_bit
        cdef int blen = self._buf_len
        cdef unsigned long long b0, b1, b2, b3, b4, val
        b0 = self._buf[addr] if addr < blen else 0
        b1 = self._buf[addr + 1] if addr + 1 < blen else 0
        b2 = self._buf[addr + 2] if addr + 2 < blen else 0
        b3 = self._buf[addr + 3] if addr + 3 < blen else 0
        b4 = self._buf[addr + 4] if addr + 4 < blen else 0
        val = (b0 << 32) | (b1 << 24) | (b2 << 16) | (b3 << 8) | b4
        return <unsigned int>((val >> (8 - bit)) & 0xFFFFFFFF)

    cpdef void addbits(self, int bits):
        cdef int total = (self.in_addr << 3) + self.in_bit + bits
        self.in_addr = total >> 3
        self.in_bit = total & 7


cdef class DecodeTable:
    cdef:
        public int max_num
        public int decode_len[16]
        public int decode_pos[16]
        public int quick_bits
        public unsigned char quick_len[1024]
        public int quick_num[1024]
        public int decode_num[306]

    def __init__(self):
        self.max_num = 0
        self.quick_bits = 0
        memset(self.decode_len, 0, 16 * sizeof(int))
        memset(self.decode_pos, 0, 16 * sizeof(int))
        memset(self.quick_len, 0, 1024)
        memset(self.quick_num, 0, 1024 * sizeof(int))
        memset(self.decode_num, 0, 306 * sizeof(int))


cpdef void make_decode_tables(
    bytearray length_table, DecodeTable dec, int size,
):
    """
    Build Huffman decode tables from bit length table.
    """
    cdef int i, cur_bit_length, upper_limit, left_aligned
    cdef int code, dist, pos
    cdef int length_count[16]
    cdef int copy_decode_pos[16]
    cdef int quick_data_size, bit_field

    dec.max_num = size

    memset(length_count, 0, 16 * sizeof(int))
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

    for i in range(16):
        copy_decode_pos[i] = dec.decode_pos[i]

    for i in range(size):
        cur_bit_length = length_table[i] & 0xF
        if cur_bit_length != 0:
            pos = copy_decode_pos[cur_bit_length]
            if pos < size:
                dec.decode_num[pos] = i
            copy_decode_pos[cur_bit_length] += 1

    if size == NC or size == 298 or size == 299:
        dec.quick_bits = MAX_QUICK_DECODE_BITS
    else:
        dec.quick_bits = MAX_QUICK_DECODE_BITS - 3

    quick_data_size = 1 << dec.quick_bits
    cur_bit_length = 1

    for code in range(quick_data_size):
        bit_field = code << (16 - dec.quick_bits)
        while cur_bit_length < 16 and bit_field >= dec.decode_len[cur_bit_length]:
            cur_bit_length += 1
        dec.quick_len[code] = <unsigned char>cur_bit_length

        dist = bit_field - dec.decode_len[cur_bit_length - 1]
        dist >>= (16 - cur_bit_length)
        pos = dec.decode_pos[cur_bit_length] + dist if cur_bit_length < 16 else 0
        if pos < size:
            dec.quick_num[code] = dec.decode_num[pos]
        else:
            dec.quick_num[code] = 0


cdef int _decode_number_fast(BitInput inp, DecodeTable dec):
    cdef int bit_field, code, bits, i, dist, pos

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


def decode_number(inp, DecodeTable dec):
    """
    Decode a Huffman symbol.
    """
    cdef int bit_field, code, bits, i, dist, pos

    if isinstance(inp, BitInput):
        return _decode_number_fast(<BitInput>inp, dec)

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


cdef int _slot_to_length(BitInput inp, int slot):
    cdef int l_bits, length
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


def slot_to_length(BitInput inp, int slot):
    """
    Convert a length slot to actual length.
    """
    return _slot_to_length(inp, slot)


cdef class BlockHeader:
    cdef:
        public int block_size
        public int block_bit_size
        public int block_start
        public int header_size
        public bint last_block
        public bint table_present

    def __init__(self):
        self.block_size = -1
        self.block_bit_size = 0
        self.block_start = 0
        self.header_size = 0
        self.last_block = False
        self.table_present = False


cdef class BlockTables:
    cdef:
        public DecodeTable LD
        public DecodeTable DD
        public DecodeTable LDD
        public DecodeTable RD
        public DecodeTable BD

    def __init__(self):
        self.LD = DecodeTable()
        self.DD = DecodeTable()
        self.LDD = DecodeTable()
        self.RD = DecodeTable()
        self.BD = DecodeTable()


cdef bint _read_block_header(BitInput inp, BlockHeader header):
    cdef int block_flags, byte_count, saved_checksum, block_size, checksum, i

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
    checksum = (0x5A ^ block_flags ^ (block_size & 0xFF)
        ^ ((block_size >> 8) & 0xFF) ^ ((block_size >> 16) & 0xFF)) & 0xFF
    if checksum != saved_checksum:
        return False

    header.block_start = inp.in_addr
    header.last_block = bool(block_flags & 0x40)
    header.table_present = bool(block_flags & 0x80)
    return True


def read_block_header(BitInput inp, BlockHeader header):
    """
    Read a RAR5 compression block header.
    """
    return _read_block_header(inp, header)


cdef bint _read_tables(BitInput inp, BlockHeader header, BlockTables tables):
    cdef int i, length, zero_count, number, n
    cdef bytearray bit_length
    cdef bytearray table
    cdef int off

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
        number = _decode_number_fast(inp, tables.BD)
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


def read_tables(BitInput inp, BlockHeader header, BlockTables tables):
    """
    Read Huffman tables from a block.
    """
    return _read_tables(inp, header, tables)


cdef int _read_filter_data(BitInput inp):
    cdef int byte_count, data, i
    byte_count = ((inp.getbits() >> 14) & 3) + 1
    inp.addbits(2)
    data = 0
    for i in range(byte_count):
        data += ((inp.getbits() >> 8) & 0xFF) << (i * 8)
        inp.addbits(8)
    return data


def read_filter_data(BitInput inp):
    """
    Read a variable-length filter data value.
    """
    return _read_filter_data(inp)


def read_filter(BitInput inp):
    """
    Read a RAR5 filter definition.
    """
    flt = UnpackFilter()
    flt.block_start = _read_filter_data(inp)
    flt.block_length = _read_filter_data(inp)
    if flt.block_length > MAX_FILTER_BLOCK_SIZE:
        flt.block_length = 0

    flt.type = (inp.getbits() >> 13) & 7
    inp.addbits(3)

    if flt.type == FilterType.FILTER_DELTA:
        flt.channels = ((inp.getbits() >> 11) & 0x1F) + 1
        inp.addbits(5)

    return flt


class Unpack50(RarUnpacker):
    """
    RAR 5.0 decompression engine
    """

    def __init__(
        self,
        data,
        int unp_size,
        int win_size,
        bint solid=False,
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
        self._filters = []
        self._tables_read = False
        self._block_header = BlockHeader()
        self._block_tables = BlockTables()
        self._write_border = min(self._win_size, UNPACK_MAX_WRITE) & self._win_mask

    def init_solid(self, data, int dest_size):
        """
        Reinitialize for the next file in a solid archive chain.
        """
        self._inp = BitInput(data)
        self._dest_size = dest_size
        self._output = bytearray()
        self._written = 0
        self._solid = True

    def _write_buf(self):
        """
        Apply filters and flush the write buffer.
        """
        cdef int mask, full_write_size, write_size_left
        cdef int block_start, block_length, block_end, first_part
        cdef int i, j
        written_border = self._wr_ptr
        mask = self._win_mask
        win = self._window
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
                            mem[:] = win[block_start:block_start + block_length]
                        else:
                            first_part = self._win_size - block_start
                            mem[:first_part] = win[block_start:]
                            mem[first_part:] = win[:block_end]

                        out_mem = apply_filter(
                            mem, flt.type, flt.channels, self._written)
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
                    self._filters = [
                        f for f in self._filters if f.type != FilterType.FILTER_NONE]
                    self._write_border = (
                        self._unp_ptr + min(self._win_size, UNPACK_MAX_WRITE)) & mask
                    return

        self._filters = [
            f for f in self._filters if f.type != FilterType.FILTER_NONE]
        self._write_area(written_border, self._unp_ptr)
        self._wr_ptr = self._unp_ptr
        self._write_border = (
            self._unp_ptr + min(self._win_size, UNPACK_MAX_WRITE)) & mask

    def decompress(self):
        """
        Run the RAR5 decompression and return the extracted data.
        """
        cdef BitInput inp = self._inp
        cdef int mask = self._win_mask
        cdef int inp_len
        cdef int main_slot, length, dist_slot, d_bits, distance
        cdef int length_slot, dist_num
        cdef int low_dist

        cdef int old0, old1, old2, old3
        cdef int unp_ptr, last_length, win_size, write_border
        cdef unsigned char *win_ptr
        cdef int src, dst, copied, chunk

        win = self._window
        win_ptr = <unsigned char *>PyByteArray_AS_STRING(win)
        win_size = self._win_size

        if not _read_block_header(inp, self._block_header):
            return self._output
        if not _read_tables(inp, self._block_header, self._block_tables):
            return self._output
        self._tables_read = True

        cdef BlockHeader hdr = self._block_header
        cdef BlockTables tbl = self._block_tables

        inp_len = inp._buf_len

        old_dist = self._old_dist
        old0 = old_dist[0]
        old1 = old_dist[1]
        old2 = old_dist[2]
        old3 = old_dist[3]
        unp_ptr = self._unp_ptr
        last_length = self._last_length
        write_border = self._write_border

        while True:
            unp_ptr &= mask

            if inp.in_addr >= inp_len:
                break

            while (inp.in_addr > hdr.block_start + hdr.block_size - 1
                or (inp.in_addr == hdr.block_start + hdr.block_size - 1
                    and inp.in_bit >= hdr.block_bit_size)):
                if hdr.last_block:
                    self._old_dist[0] = old0
                    self._old_dist[1] = old1
                    self._old_dist[2] = old2
                    self._old_dist[3] = old3
                    self._unp_ptr = unp_ptr
                    self._last_length = last_length
                    self._write_buf()
                    return self._output
                if not _read_block_header(inp, hdr) or not _read_tables(inp, hdr, tbl):
                    self._old_dist[0] = old0
                    self._old_dist[1] = old1
                    self._old_dist[2] = old2
                    self._old_dist[3] = old3
                    self._unp_ptr = unp_ptr
                    self._last_length = last_length
                    self._write_buf()
                    return self._output

            if (((write_border - unp_ptr) & mask) < MAX_INC_LZ_MATCH
                    and write_border != unp_ptr):
                self._old_dist[0] = old0
                self._old_dist[1] = old1
                self._old_dist[2] = old2
                self._old_dist[3] = old3
                self._unp_ptr = unp_ptr
                self._last_length = last_length
                self._write_buf()
                write_border = self._write_border
                if self._written > self._dest_size:
                    return self._output

            main_slot = _decode_number_fast(inp, tbl.LD)

            if main_slot < 256:
                win_ptr[unp_ptr] = <unsigned char>(main_slot & 0xFF)
                unp_ptr = (unp_ptr + 1) & mask
                continue

            if main_slot >= 262:
                length = _slot_to_length(inp, main_slot - 262)

                dist_slot = _decode_number_fast(inp, tbl.DD)
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
                        low_dist = _decode_number_fast(inp, tbl.LDD)
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

                old3 = old2
                old2 = old1
                old1 = old0
                old0 = distance
                last_length = length

                src = (unp_ptr - distance) & mask
                dst = unp_ptr
                if src + length <= win_size and dst + length <= win_size:
                    if distance >= length:
                        memcpy(&win_ptr[dst], &win_ptr[src], length)
                    else:
                        copied = 0
                        while copied < length:
                            chunk = distance if distance < length - copied else length - copied
                            memcpy(&win_ptr[dst + copied], &win_ptr[src + copied], chunk)
                            copied += chunk
                    unp_ptr = (dst + length) & mask
                else:
                    src = unp_ptr - distance
                    dst = unp_ptr
                    while length > 0:
                        win_ptr[dst & mask] = win_ptr[src & mask]
                        src += 1
                        dst += 1
                        length -= 1
                    unp_ptr = dst & mask
                continue

            if main_slot == 256:
                self._unp_ptr = unp_ptr
                flt = read_filter(inp)
                if flt is None:
                    break
                flt.next_window = (self._wr_ptr != unp_ptr
                    and ((self._wr_ptr - unp_ptr) & mask) <= flt.block_start)
                flt.block_start = (flt.block_start + unp_ptr) & mask
                if len(self._filters) >= MAX_UNPACK_FILTERS:
                    self._old_dist[0] = old0
                    self._old_dist[1] = old1
                    self._old_dist[2] = old2
                    self._old_dist[3] = old3
                    self._last_length = last_length
                    self._write_buf()
                    write_border = self._write_border
                    if len(self._filters) >= MAX_UNPACK_FILTERS:
                        self._filters.clear()
                self._filters.append(flt)
                continue

            if main_slot == 257:
                if last_length != 0:
                    distance = old0
                    length = last_length
                    src = (unp_ptr - distance) & mask
                    dst = unp_ptr
                    if src + length <= win_size and dst + length <= win_size:
                        if distance >= length:
                            memcpy(&win_ptr[dst], &win_ptr[src], length)
                        else:
                            copied = 0
                            while copied < length:
                                chunk = distance if distance < length - copied else length - copied
                                memcpy(
                                    &win_ptr[dst + copied], &win_ptr[src + copied], chunk)
                                copied += chunk
                        unp_ptr = (dst + length) & mask
                    else:
                        src = unp_ptr - distance
                        dst = unp_ptr
                        while length > 0:
                            win_ptr[dst & mask] = win_ptr[src & mask]
                            src += 1
                            dst += 1
                            length -= 1
                        unp_ptr = dst & mask
                continue

            if main_slot < 262:
                dist_num = main_slot - 258
                if dist_num == 0:
                    distance = old0
                elif dist_num == 1:
                    distance = old1
                    old1 = old0
                    old0 = distance
                elif dist_num == 2:
                    distance = old2
                    old2 = old1
                    old1 = old0
                    old0 = distance
                else:
                    distance = old3
                    old3 = old2
                    old2 = old1
                    old1 = old0
                    old0 = distance

                length_slot = _decode_number_fast(inp, tbl.RD)
                length = _slot_to_length(inp, length_slot)
                last_length = length

                src = (unp_ptr - distance) & mask
                dst = unp_ptr
                if src + length <= win_size and dst + length <= win_size:
                    if distance >= length:
                        memcpy(&win_ptr[dst], &win_ptr[src], length)
                    else:
                        copied = 0
                        while copied < length:
                            chunk = distance if distance < length - copied else length - copied
                            memcpy(&win_ptr[dst + copied], &win_ptr[src + copied], chunk)
                            copied += chunk
                    unp_ptr = (dst + length) & mask
                else:
                    src = unp_ptr - distance
                    dst = unp_ptr
                    while length > 0:
                        win_ptr[dst & mask] = win_ptr[src & mask]
                        src += 1
                        dst += 1
                        length -= 1
                    unp_ptr = dst & mask
                continue

        self._old_dist[0] = old0
        self._old_dist[1] = old1
        self._old_dist[2] = old2
        self._old_dist[3] = old3
        self._unp_ptr = unp_ptr
        self._last_length = last_length
        self._write_buf()
        return self._output
