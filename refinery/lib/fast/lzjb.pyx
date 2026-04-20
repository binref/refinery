# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True
cimport cython

from libc.stdint cimport uint8_t, uint16_t, uint32_t
from libc.stdlib cimport free, malloc, realloc
from libc.string cimport memcpy

DEF MATCH_LEN = 6
DEF MATCH_MIN = 3
DEF MATCH_MAX = (1 << MATCH_LEN) + (MATCH_MIN - 1)
DEF OFFSET_MASK = (1 << (16 - MATCH_LEN)) - 1
DEF LEMPEL_SIZE = 0x1000


cdef void _ensure_capacity(
    uint8_t **buf, uint32_t *cap, uint32_t needed
) except * nogil:
    cdef uint32_t new_cap
    cdef uint8_t *tmp
    if needed <= cap[0]:
        return
    new_cap = cap[0]
    while new_cap < needed:
        new_cap = new_cap * 2
    tmp = <uint8_t *>realloc(buf[0], new_cap)
    if tmp == NULL:
        with gil:
            raise MemoryError
    buf[0] = tmp
    cap[0] = new_cap


def lzjb_decompress(data) -> bytearray:
    cdef:
        const uint8_t[::1] src = memoryview(data)
        int end = len(data)
        int pos = 0
        uint8_t copy_byte
        uint8_t mask
        uint16_t pair
        uint32_t match_len, match_pos, dst_len
        uint32_t cursor = 0
        uint32_t out_cap
        uint8_t *out_buf
        uint32_t copy_src, copy_len

    if end == 0:
        return bytearray()

    out_cap = <uint32_t>(end * 3) if end < 0x20000000 else <uint32_t>end
    if out_cap < 256:
        out_cap = 256
    out_buf = <uint8_t *>malloc(out_cap)
    if out_buf == NULL:
        raise MemoryError

    try:
        while pos < end:
            copy_byte = src[pos]
            pos += 1

            if copy_byte == 0:
                # Fast path: no back-references in this group, copy up to 8 literals
                copy_len = <uint32_t>(end - pos)
                if copy_len > 8:
                    copy_len = 8
                _ensure_capacity(&out_buf, &out_cap, cursor + copy_len)
                memcpy(&out_buf[cursor], &src[pos], copy_len)
                cursor += copy_len
                pos += copy_len
                continue

            mask = 0x01
            while mask != 0 and pos < end:
                if not (copy_byte & mask):
                    _ensure_capacity(&out_buf, &out_cap, cursor + 1)
                    out_buf[cursor] = src[pos]
                    cursor += 1
                    pos += 1
                else:
                    if cursor == 0:
                        raise ValueError('copy requested against empty buffer')
                    if pos + 1 >= end:
                        break
                    pair = (<uint16_t>src[pos] << 8) | <uint16_t>src[pos + 1]
                    pos += 2
                    match_len = (pair >> 10) + MATCH_MIN
                    match_pos = pair & 0x3FF
                    if match_pos == 0 or match_pos > cursor:
                        raise RuntimeError('invalid match offset')
                    copy_src = cursor - match_pos
                    _ensure_capacity(&out_buf, &out_cap, cursor + match_len)
                    copy_len = match_len
                    while copy_len > 0:
                        dst_len = cursor - copy_src
                        if dst_len > copy_len:
                            dst_len = copy_len
                        memcpy(&out_buf[cursor], &out_buf[copy_src], dst_len)
                        cursor += dst_len
                        copy_src += dst_len
                        copy_len -= dst_len
                mask <<= 1

        return bytearray(out_buf[:cursor])
    finally:
        free(out_buf)


def lzjb_compress(data) -> bytearray:
    cdef:
        const uint8_t[::1] src = memoryview(data)
        int length = len(data)
        int position = 0
        uint32_t copymask = 0x80
        int copy_map = -1
        uint32_t hsh, offset, cpy, mlen, max_mlen
        uint32_t cursor = 0
        uint32_t out_cap
        uint8_t *out_buf
        uint32_t lempel[LEMPEL_SIZE]
        int i

    if length == 0:
        return bytearray()

    out_cap = <uint32_t>length if length > 256 else 256
    out_buf = <uint8_t *>malloc(out_cap)
    if out_buf == NULL:
        raise MemoryError

    for i in range(LEMPEL_SIZE):
        lempel[i] = 0

    try:
        while position < length:
            copymask <<= 1
            if copymask >= 0x100:
                copymask = 1
                copy_map = <int>cursor
                _ensure_capacity(&out_buf, &out_cap, cursor + 1)
                out_buf[cursor] = 0
                cursor += 1

            if position > length - MATCH_MAX:
                _ensure_capacity(&out_buf, &out_cap, cursor + 1)
                out_buf[cursor] = src[position]
                cursor += 1
                position += 1
                continue

            hsh = (<uint32_t>src[position] << 16) + (<uint32_t>src[position + 1] << 8) + <uint32_t>src[position + 2]
            hsh += hsh >> 9
            hsh += hsh >> 5
            hsh = hsh % LEMPEL_SIZE
            offset = (<uint32_t>position - lempel[hsh]) & OFFSET_MASK
            lempel[hsh] = <uint32_t>position
            cpy = <uint32_t>position - offset

            if (
                cpy < <uint32_t>position
                and src[position] == src[cpy]
                and src[position + 1] == src[cpy + 1]
                and src[position + 2] == src[cpy + 2]
            ):
                if copy_map < 0:
                    raise ValueError
                out_buf[copy_map] |= <uint8_t>copymask
                max_mlen = <uint32_t>(length - position)
                if max_mlen > MATCH_MAX:
                    max_mlen = MATCH_MAX
                mlen = MATCH_MIN
                while mlen < max_mlen:
                    if src[position + mlen] != src[cpy + mlen]:
                        break
                    mlen += 1
                _ensure_capacity(&out_buf, &out_cap, cursor + 2)
                out_buf[cursor] = <uint8_t>(((mlen - MATCH_MIN) << (8 - MATCH_LEN)) | (offset >> 8))
                cursor += 1
                out_buf[cursor] = <uint8_t>(offset & 0xFF)
                cursor += 1
                position += mlen
            else:
                _ensure_capacity(&out_buf, &out_cap, cursor + 1)
                out_buf[cursor] = src[position]
                cursor += 1
                position += 1

        return bytearray(out_buf[:cursor])
    finally:
        free(out_buf)
