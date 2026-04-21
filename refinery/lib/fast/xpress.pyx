# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True
cimport cython

from libc.stdint cimport int32_t, uint8_t, uint16_t, uint32_t, uint64_t
from libc.stdlib cimport free, malloc, realloc
from libc.string cimport memcpy, memset

DEF XPRESS_NUM_CHARS = 256
DEF XPRESS_NUM_SYMBOLS = 512
DEF XPRESS_MAX_CODEWORD_LEN = 15
DEF XPRESS_MIN_MATCH_LEN = 3
DEF XPRESS_TABLEBITS = 11

DEF _SHIFT = 4
DEF _MASK = (1 << _SHIFT) - 1


cdef int _ensure(uint8_t **buf, uint32_t *cap, uint32_t needed) except -1 nogil:
    cdef uint32_t nc
    cdef uint8_t *tmp
    if needed <= cap[0]:
        return 0
    nc = cap[0]
    while nc < needed:
        nc = nc * 2
    tmp = <uint8_t *>realloc(buf[0], nc)
    if tmp == NULL:
        with gil:
            raise MemoryError
    buf[0] = tmp
    cap[0] = nc
    return 0


cdef inline int _out_byte(
    uint8_t **buf, uint32_t *cap, uint32_t *length, uint8_t b
) except -1 nogil:
    _ensure(buf, cap, length[0] + 1)
    buf[0][length[0]] = b
    length[0] += 1
    return 0


cdef int _replay(
    uint8_t **buf, uint32_t *cap, uint32_t *length,
    uint32_t offset, uint32_t match_len
) except -1 nogil:
    cdef uint32_t start, chunk_len, pos
    _ensure(buf, cap, length[0] + match_len)
    start = length[0] - offset
    pos = length[0]
    while match_len > 0:
        chunk_len = pos - start
        if chunk_len > match_len:
            chunk_len = match_len
        if chunk_len == 0:
            with gil:
                raise ValueError('zero-length replay')
        memcpy(&buf[0][pos], &buf[0][start], chunk_len)
        pos += chunk_len
        start += chunk_len
        match_len -= chunk_len
    length[0] = pos
    return 0


cdef int32_t _s32shift(int32_t k, int shift) noexcept nogil:
    cdef uint32_t M = <uint32_t>(1) << 32
    shift = shift % 32
    k = <int32_t>((<uint32_t>k * (<uint32_t>(1) << shift)) % M)
    return k


cdef int _make_decode_table(
    uint16_t *decode_table,
    const uint8_t *table_data,
    int sym_count,
    int table_bits,
    int max_codeword_len,
) except -1:
    cdef int len_counts[32]
    cdef int offsets[32]
    cdef int sorted_syms[XPRESS_NUM_SYMBOLS]
    cdef int remainder, codeword_length, entry_pos
    cdef int stores_per_loop, end_sym_idx, sym_index
    cdef int i, k
    cdef uint16_t entry
    cdef int codeword, subtable_pos, subtable_bits, subtable_prefix
    cdef int prefix, count, end_pos

    memset(len_counts, 0, 32 * sizeof(int))
    for i in range(sym_count):
        len_counts[table_data[i]] += 1

    remainder = 1
    for i in range(1, max_codeword_len + 1):
        remainder = (remainder << 1) - len_counts[i]
        if remainder < 0:
            raise OverflowError('Lengths have overflowed the code space.')
    if remainder:
        if remainder != 1 << max_codeword_len:
            raise RuntimeError('Incomplete & nonempty code encountered.')
        memset(decode_table, 0, (1 << table_bits) * sizeof(uint16_t))
        return 0

    memset(offsets, 0, 32 * sizeof(int))
    for i in range(max_codeword_len):
        offsets[i + 1] = offsets[i] + len_counts[i]

    memset(sorted_syms, 0, XPRESS_NUM_SYMBOLS * sizeof(int))
    for i in range(sym_count):
        k = table_data[i]
        sorted_syms[offsets[k]] = i
        offsets[k] += 1

    sym_index = offsets[0]
    codeword_length = 1
    entry_pos = 0
    stores_per_loop = 1 << (table_bits - codeword_length)

    while stores_per_loop > 0:
        end_sym_idx = sym_index + len_counts[codeword_length]
        for k in range(sym_index, end_sym_idx):
            entry = <uint16_t>((sorted_syms[k] << _SHIFT) | codeword_length)
            for i in range(stores_per_loop):
                decode_table[entry_pos + i] = entry
            entry_pos += stores_per_loop
        codeword_length += 1
        sym_index = end_sym_idx
        stores_per_loop >>= 1

    if sym_index >= sym_count:
        return 0

    codeword = entry_pos * 2
    subtable_pos = 1 << table_bits
    subtable_bits = table_bits
    subtable_prefix = -1

    while sym_index < sym_count:
        while len_counts[codeword_length] == 0:
            if codeword_length > sym_count:
                raise IndexError('Error computing codeword')
            codeword_length += 1
            codeword <<= 1

        prefix = codeword >> (codeword_length - table_bits)

        if prefix != subtable_prefix:
            subtable_prefix = prefix
            subtable_bits = codeword_length - table_bits
            remainder = _s32shift(1, subtable_bits)
            while True:
                remainder -= len_counts[table_bits + subtable_bits]
                if remainder <= 0:
                    break
                subtable_bits += 1
                remainder <<= 1
            decode_table[subtable_prefix] = <uint16_t>((subtable_pos << _SHIFT) | subtable_bits)

        entry = <uint16_t>((sorted_syms[sym_index] << _SHIFT) | (codeword_length - table_bits))
        count = 1 << (table_bits + subtable_bits - codeword_length)
        end_pos = subtable_pos + count
        for i in range(subtable_pos, end_pos):
            decode_table[i] = entry
        subtable_pos = end_pos
        len_counts[codeword_length] -= 1
        codeword += 1
        sym_index += 1

    return 0


def xpress_decompress(data, int target) -> bytearray:
    """
    XPRESS (plain) decompression. The format interleaves 32-bit flag words with data bytes: each
    flag word provides 32 single-bit flags, and between flag words the data bytes (literals, match
    descriptors, extended lengths) are read sequentially.
    """
    cdef:
        const uint8_t[::1] src_view = memoryview(data)
        const uint8_t *src = &src_view[0]
        int end = len(src_view)
        int pos = 0
        uint32_t flags = 0
        int flag_cnt = 0
        uint8_t *out_buf
        uint32_t out_cap, out_len
        int nibble_cache = -1
        uint16_t val
        int moffset, length, length_pair

    out_cap = <uint32_t>(end * 4) if end < 0x10000000 else <uint32_t>end
    if out_cap < 256:
        out_cap = 256
    out_buf = <uint8_t *>malloc(out_cap)
    if out_buf == NULL:
        raise MemoryError
    out_len = 0

    try:
        while pos < end or flag_cnt > 0:
            if target > 0 and <int>out_len >= target:
                break

            if flag_cnt == 0:
                if pos + 3 >= end:
                    break
                flags = (
                    <uint32_t>src[pos]
                    | (<uint32_t>src[pos + 1] << 8)
                    | (<uint32_t>src[pos + 2] << 16)
                    | (<uint32_t>src[pos + 3] << 24)
                )
                pos += 4
                flag_cnt = 32

            if not (flags >> 31):
                flags <<= 1
                flag_cnt -= 1
                if pos >= end:
                    break
                _out_byte(&out_buf, &out_cap, &out_len, src[pos])
                pos += 1
                continue

            flags <<= 1
            flag_cnt -= 1
            if pos + 1 >= end:
                break
            val = <uint16_t>src[pos] | (<uint16_t>src[pos + 1] << 8)
            pos += 2
            moffset = (val >> 3) + 1
            length = val & 7

            if length == 7:
                if nibble_cache >= 0:
                    length = nibble_cache
                    nibble_cache = -1
                else:
                    if pos >= end:
                        break
                    length_pair = src[pos]
                    pos += 1
                    nibble_cache = length_pair >> 4
                    length = length_pair & 0xF
                if length == 15:
                    if pos >= end:
                        break
                    length = src[pos]
                    pos += 1
                    if length == 0xFF:
                        if pos + 1 >= end:
                            break
                        length = <int>src[pos] | (<int>src[pos + 1] << 8)
                        pos += 2
                        if length == 0:
                            if pos + 3 >= end:
                                break
                            length = (
                                <int>src[pos]
                                | (<int>src[pos + 1] << 8)
                                | (<int>src[pos + 2] << 16)
                                | (<int>src[pos + 3] << 24)
                            )
                            pos += 4
                        length -= 22
                        if length < 0:
                            raise RuntimeError('Invalid match length')
                    length += 15
                length += 7
            length += 3

            if <uint32_t>moffset > out_len:
                raise ValueError('offset exceeds output')
            _replay(&out_buf, &out_cap, &out_len, <uint32_t>moffset, <uint32_t>length)

        return bytearray(out_buf[:out_len])
    finally:
        free(out_buf)


def xpress_huffman_decompress(data, int target, int max_chunk_size=0x10000) -> bytearray:
    """
    XPRESS with Huffman decompression. Uses MSB-first bit ordering matching BitBufferedReader
    semantics. Bits are consumed from the top of the buffer. The byte stream position (pos) is
    always right after the last 16-bit word loaded into the bit buffer; extended-length bytes are
    read from pos.
    """
    cdef:
        const uint8_t[::1] src_view = memoryview(data)
        const uint8_t *src = &src_view[0]
        int end = len(src_view)
        int pos = 0
        uint8_t *out_buf
        uint32_t out_cap, out_len
        int limit = 0
        uint16_t decode_table[1 << (XPRESS_TABLEBITS + 1)]
        uint8_t tbl_data[XPRESS_NUM_SYMBOLS]
        uint64_t bit_buf
        int bit_cnt
        uint16_t entry
        int sym, length, match_length, offsetlog
        int offset
        int nudge
        int i, remainder, skip
        uint64_t top_bits
        int need

    out_cap = <uint32_t>(end * 4) if end < 0x10000000 else <uint32_t>end
    if out_cap < 256:
        out_cap = 256
    out_buf = <uint8_t *>malloc(out_cap)
    if out_buf == NULL:
        raise MemoryError
    out_len = 0

    try:
        while pos < end:
            if XPRESS_NUM_SYMBOLS // 2 > end - pos:
                raise IndexError(
                    F'There are only {end - pos} bytes remaining, '
                    F'but at least {XPRESS_NUM_SYMBOLS // 2} are required for a Huffman table.')

            for i in range(XPRESS_NUM_SYMBOLS):
                tbl_data[i] = (src[pos + i // 2] >> (4 * (i & 1))) & 0xF
            pos += XPRESS_NUM_SYMBOLS // 2

            _make_decode_table(decode_table, tbl_data, XPRESS_NUM_SYMBOLS, XPRESS_TABLEBITS, XPRESS_MAX_CODEWORD_LEN)

            limit += max_chunk_size
            bit_buf = 0
            bit_cnt = 0

            while True:
                if <int>out_len == target:
                    return bytearray(out_buf[:out_len])
                if <int>out_len >= limit:
                    need = 16 - bit_cnt
                    if need > 0:
                        need = ((need + 15) // 16) * 16
                        if pos + (need // 8) <= end:
                            for i in range(need // 16):
                                bit_buf = (bit_buf << 16) | <uint64_t>src[pos] | (<uint64_t>src[pos + 1] << 8)
                                bit_cnt += 16
                                pos += 2
                    bit_buf = 0
                    bit_cnt = 0
                    break

                need = XPRESS_MAX_CODEWORD_LEN - bit_cnt
                if need > 0:
                    need = ((need + 15) // 16) * 16
                    for i in range(need // 16):
                        if pos + 1 >= end:
                            break
                        bit_buf = (bit_buf << 16) | <uint64_t>src[pos] | (<uint64_t>src[pos + 1] << 8)
                        bit_cnt += 16
                        pos += 2
                if bit_cnt < XPRESS_TABLEBITS:
                    break

                top_bits = bit_buf >> (bit_cnt - XPRESS_TABLEBITS)
                entry = decode_table[top_bits & ((1 << XPRESS_TABLEBITS) - 1)]
                sym = entry >> _SHIFT
                length = entry & _MASK

                if entry >= (1 << (XPRESS_TABLEBITS + _SHIFT)):
                    bit_cnt -= XPRESS_TABLEBITS
                    need = XPRESS_MAX_CODEWORD_LEN - bit_cnt
                    if need > 0:
                        need = ((need + 15) // 16) * 16
                        for i in range(need // 16):
                            if pos + 1 >= end:
                                break
                            bit_buf = (bit_buf << 16) | <uint64_t>src[pos] | (<uint64_t>src[pos + 1] << 8)
                            bit_cnt += 16
                            pos += 2
                    top_bits = bit_buf >> (bit_cnt - length)
                    entry = decode_table[sym + <int>(top_bits & ((<uint64_t>1 << length) - 1))]
                    sym = entry >> _SHIFT
                    length = entry & _MASK

                bit_cnt -= length

                if sym < XPRESS_NUM_CHARS:
                    _out_byte(&out_buf, &out_cap, &out_len, <uint8_t>sym)
                    continue

                match_length = sym & 0xF
                offsetlog = (sym >> 4) & 0xF

                # BitBufferedReader.collect() equivalent: ensure at least 16 bits before offset read
                need = 16 - bit_cnt
                if need > 0:
                    need = ((need + 15) // 16) * 16
                    for i in range(need // 16):
                        if pos + 1 >= end:
                            break
                        bit_buf = (bit_buf << 16) | <uint64_t>src[pos] | (<uint64_t>src[pos + 1] << 8)
                        bit_cnt += 16
                        pos += 2

                if offsetlog > 0:
                    top_bits = bit_buf >> (bit_cnt - offsetlog)
                    offset = (1 << offsetlog) | <int>(top_bits & ((<uint64_t>1 << offsetlog) - 1))
                    bit_cnt -= offsetlog
                else:
                    offset = 1

                if match_length == 0xF:
                    if pos >= end:
                        break
                    nudge = src[pos]
                    pos += 1
                    if nudge < 0xFF:
                        match_length += nudge
                    else:
                        if pos + 1 >= end:
                            break
                        match_length = <int>src[pos] | (<int>src[pos + 1] << 8)
                        pos += 2
                        if match_length == 0:
                            if pos + 3 >= end:
                                break
                            match_length = (
                                <int>src[pos]
                                | (<int>src[pos + 1] << 8)
                                | (<int>src[pos + 2] << 16)
                                | (<int>src[pos + 3] << 24)
                            )
                            pos += 4
                    bit_buf = 0
                    bit_cnt = 0
                match_length += XPRESS_MIN_MATCH_LEN

                if <uint32_t>offset > out_len:
                    raise ValueError('offset exceeds output')
                _replay(&out_buf, &out_cap, &out_len, <uint32_t>offset, <uint32_t>match_length)

        return bytearray(out_buf[:out_len])
    finally:
        free(out_buf)
