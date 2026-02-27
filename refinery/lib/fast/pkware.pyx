# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True
cimport cython

from libc.stdint cimport uint8_t, uint32_t, uint64_t
from libc.stdlib cimport free, malloc, realloc
from libc.string cimport memcpy

from refinery.lib.fast._pkware_tables import _COPY_LENGTHS, _COPY_OFFSETS, _LITERALS

# Maximum code lengths per table; peek tables are 2^N entries each.
DEF LIT_BITS = 13
DEF LIT_SIZE = 8192
DEF LEN_BITS = 15
DEF LEN_SIZE = 32768
DEF OFF_BITS = 8
DEF OFF_SIZE = 256
DEF EMPTY = 0xFFFFFFFF

# Peek tables: entry = (symbol << 8) | code_length, or EMPTY.
cdef uint32_t _lit_peek[LIT_SIZE]
cdef uint32_t _len_peek[LEN_SIZE]
cdef uint32_t _off_peek[OFF_SIZE]


cdef inline uint32_t _bit_reverse(uint32_t value, int length):
    cdef uint32_t result = 0
    cdef int i
    for i in range(length):
        result = (result << 1) | (value & 1)
        value >>= 1
    return result


cdef _init_peek_table(uint32_t *table, int max_bits, int table_size, dict source):
    cdef int i
    cdef uint32_t reversed_code, ext
    cdef int code_length, extra_bits
    cdef uint32_t code_value, symbol

    for i in range(table_size):
        table[i] = EMPTY

    for (code_length, code_value), symbol in source.items():
        reversed_code = _bit_reverse(code_value, code_length)
        extra_bits = max_bits - code_length
        for ext in range(<uint32_t>(1 << extra_bits)):
            table[reversed_code | (ext << code_length)] = (symbol << 8) | <uint32_t>code_length


_init_peek_table(_lit_peek, LIT_BITS, LIT_SIZE, _LITERALS)
_init_peek_table(_len_peek, LEN_BITS, LEN_SIZE, _COPY_LENGTHS)
_init_peek_table(_off_peek, OFF_BITS, OFF_SIZE, _COPY_OFFSETS)


class PKWareError(Exception):
    def __init__(self, msg, partial):
        super().__init__(msg)
        self.partial = partial


def pkware_decompress(data) -> bytearray:
    cdef:
        const uint8_t[::1] src = memoryview(data)
        int end = len(data)
        int pos = 2
        uint64_t bbits = 0
        int nbits = 0
        uint8_t codelit = src[0]
        uint8_t maxdict = src[1]
        uint32_t bit
        uint32_t code, entry
        int bits
        uint32_t length, offset, more
        uint32_t cursor = 0
        uint32_t out_cap
        uint32_t copy_src, copy_len
        uint8_t *out_buf

    if codelit > 1:
        raise ValueError(f'Invalid literal encoding value {codelit}.')
    if maxdict < 4 or maxdict > 6:
        raise ValueError(f'Invalid dictionary size {maxdict}.')

    # Initial output buffer allocation: decompressed data is always larger
    out_cap = <uint32_t>((end - 2) * 4) if end > 2 else 256
    if out_cap < 256:
        out_cap = 256
    out_buf = <uint8_t *>malloc(out_cap)
    if out_buf == NULL:
        raise MemoryError

    try:
        while pos < end or nbits > 0:
          try:
            # Fill at least 1 bit
            while nbits < 1 and pos < end:
                bbits |= (<uint64_t>src[pos]) << nbits
                pos += 1
                nbits += 8
            if nbits < 1:
                break
            bit = <uint32_t>(bbits & 1)
            bbits >>= 1
            nbits -= 1

            if bit == 0:
                # Literal byte
                if codelit:
                    # Fill buffer for peek-table lookup
                    while nbits < LIT_BITS and pos < end:
                        bbits |= (<uint64_t>src[pos]) << nbits
                        pos += 1
                        nbits += 8
                    if nbits < 1:
                        break
                    entry = _lit_peek[<uint32_t>(bbits & (LIT_SIZE - 1))]
                    if entry == EMPTY:
                        raise ValueError(
                            'Failed to decode a symbol in the compressed data stream.')
                    bits = <int>(entry & 0xFF)
                    if bits > nbits:
                        break
                    code = entry >> 8
                    bbits >>= bits
                    nbits -= bits
                else:
                    # Uncoded: read 8 bits
                    while nbits < 8 and pos < end:
                        bbits |= (<uint64_t>src[pos]) << nbits
                        pos += 1
                        nbits += 8
                    if nbits < 8:
                        break
                    code = <uint32_t>(bbits & 0xFF)
                    bbits >>= 8
                    nbits -= 8

                # Ensure output capacity
                if cursor >= out_cap:
                    out_cap = out_cap * 2
                    out_buf = <uint8_t *>realloc(out_buf, out_cap)
                    if out_buf == NULL:
                        raise MemoryError
                out_buf[cursor] = <uint8_t>code
                cursor += 1
            else:
                # Copy command: decode length from peek table
                while nbits < LEN_BITS and pos < end:
                    bbits |= (<uint64_t>src[pos]) << nbits
                    pos += 1
                    nbits += 8
                if nbits < 1:
                    break
                entry = _len_peek[<uint32_t>(bbits & (LEN_SIZE - 1))]
                if entry == EMPTY:
                    raise ValueError(
                        'Failed to decode a symbol in the compressed data stream.')
                bits = <int>(entry & 0xFF)
                if bits > nbits:
                    break
                length = entry >> 8
                bbits >>= bits
                nbits -= bits

                if length == 519:
                    break

                # Decode offset from peek table
                while nbits < OFF_BITS and pos < end:
                    bbits |= (<uint64_t>src[pos]) << nbits
                    pos += 1
                    nbits += 8
                if nbits < 1:
                    break
                entry = _off_peek[<uint32_t>(bbits & (OFF_SIZE - 1))]
                if entry == EMPTY:
                    raise ValueError(
                        'Failed to decode a symbol in the compressed data stream.')
                bits = <int>(entry & 0xFF)
                if bits > nbits:
                    break
                offset = entry >> 8
                bbits >>= bits
                nbits -= bits

                # Read extra offset bits
                more = 2 if length == 2 else maxdict
                while nbits < <int>more and pos < end:
                    bbits |= (<uint64_t>src[pos]) << nbits
                    pos += 1
                    nbits += 8
                if nbits < <int>more:
                    break
                offset <<= more
                offset += <uint32_t>(bbits & ((1 << more) - 1))
                bbits >>= more
                nbits -= more
                offset += 1

                # Ensure output capacity for the back-reference copy
                while cursor + length > out_cap:
                    out_cap = out_cap * 2
                    out_buf = <uint8_t *>realloc(out_buf, out_cap)
                    if out_buf == NULL:
                        raise MemoryError

                # Back-reference copy
                copy_src = cursor - offset
                copy_len = length
                if offset >= copy_len:
                    memcpy(&out_buf[cursor], &out_buf[copy_src], copy_len)
                else:
                    while copy_len >= offset:
                        memcpy(&out_buf[cursor + (length - copy_len)], &out_buf[copy_src], offset)
                        copy_len -= offset
                    if copy_len > 0:
                        memcpy(&out_buf[cursor + (length - copy_len)], &out_buf[copy_src], copy_len)

                cursor += length
          except Exception as _E:
            if cursor == 0:
                raise
            raise PKWareError(str(_E), bytearray(out_buf[:cursor])) from _E

        return bytearray(out_buf[:cursor])
    finally:
        free(out_buf)
