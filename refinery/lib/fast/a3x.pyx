# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True
cimport cython

from libc.stdint cimport uint8_t, uint32_t, uint64_t
from libc.stdlib cimport free, malloc
from libc.string cimport memcpy


cdef inline uint32_t _rotl32(uint32_t v, int n) noexcept nogil:
    return (v << n) | (v >> (32 - n))


def a3x_decompress(data, bint is_current):
    cdef:
        const uint8_t[::1] view = memoryview(data)
        uint32_t size
        const uint8_t[::1] src
        int src_len
        int src_pos = 0
        uint32_t bit_buffer = 0
        int bit_count = 0
        uint32_t cursor = 0
        uint32_t check
        uint32_t offset
        uint32_t length
        uint32_t delta
        uint32_t out_len
        uint32_t start
        uint32_t rep, r
        int i
        uint8_t byte_val
        uint8_t *out_buf
        uint32_t copy_src, copy_len

    size = (
        (<uint32_t>view[4] << 24) |
        (<uint32_t>view[5] << 16) |
        (<uint32_t>view[6] << 8) |
        (<uint32_t>view[7])
    )

    src_bytes = bytes(data[8:])
    src = src_bytes
    src_len = len(src_bytes)

    out_buf = <uint8_t *>malloc(size)
    if out_buf == NULL:
        raise MemoryError

    try:
        while cursor < size:
            # inline _bits(1)
            while bit_count < 1:
                if src_pos >= src_len:
                    raise EOFError
                bit_buffer = (bit_buffer << 8) | src[src_pos]
                src_pos += 1
                bit_count += 8
            bit_count -= 1
            check = (bit_buffer >> bit_count) & 1
            bit_buffer &= (1 << bit_count) - 1

            if check == <uint32_t>is_current:
                # inline _bits(8)
                while bit_count < 8:
                    if src_pos >= src_len:
                        raise EOFError
                    bit_buffer = (bit_buffer << 8) | src[src_pos]
                    src_pos += 1
                    bit_count += 8
                bit_count -= 8
                byte_val = (bit_buffer >> bit_count) & 0xFF
                bit_buffer &= (1 << bit_count) - 1
                out_buf[cursor] = byte_val
                cursor += 1
                continue

            # inline _bits(15)
            while bit_count < 15:
                if src_pos >= src_len:
                    raise EOFError
                bit_buffer = (bit_buffer << 8) | src[src_pos]
                src_pos += 1
                bit_count += 8
            bit_count -= 15
            offset = (bit_buffer >> bit_count) & 0x7FFF
            bit_buffer &= (1 << bit_count) - 1

            # inline _bits(2)
            while bit_count < 2:
                if src_pos >= src_len:
                    raise EOFError
                bit_buffer = (bit_buffer << 8) | src[src_pos]
                src_pos += 1
                bit_count += 8
            bit_count -= 2
            length = (bit_buffer >> bit_count) & 0x3
            bit_buffer &= (1 << bit_count) - 1

            delta = 0
            if length == 3:
                delta = 3
                # inline _bits(3)
                while bit_count < 3:
                    if src_pos >= src_len:
                        raise EOFError
                    bit_buffer = (bit_buffer << 8) | src[src_pos]
                    src_pos += 1
                    bit_count += 8
                bit_count -= 3
                length = (bit_buffer >> bit_count) & 0x7
                bit_buffer &= (1 << bit_count) - 1

                if length == 7:
                    delta = 0x0A
                    # inline _bits(5)
                    while bit_count < 5:
                        if src_pos >= src_len:
                            raise EOFError
                        bit_buffer = (bit_buffer << 8) | src[src_pos]
                        src_pos += 1
                        bit_count += 8
                    bit_count -= 5
                    length = (bit_buffer >> bit_count) & 0x1F
                    bit_buffer &= (1 << bit_count) - 1

                    if length == 0x1F:
                        delta = 0x029
                        # inline _bits(8)
                        while bit_count < 8:
                            if src_pos >= src_len:
                                raise EOFError
                            bit_buffer = (bit_buffer << 8) | src[src_pos]
                            src_pos += 1
                            bit_count += 8
                        bit_count -= 8
                        length = (bit_buffer >> bit_count) & 0xFF
                        bit_buffer &= (1 << bit_count) - 1

                        if length == 0xFF:
                            delta = 0x128
                            # inline _bits(8)
                            while bit_count < 8:
                                if src_pos >= src_len:
                                    raise EOFError
                                bit_buffer = (bit_buffer << 8) | src[src_pos]
                                src_pos += 1
                                bit_count += 8
                            bit_count -= 8
                            length = (bit_buffer >> bit_count) & 0xFF
                            bit_buffer &= (1 << bit_count) - 1

            while length == 0xFF:
                delta += 0xFF
                # inline _bits(8)
                while bit_count < 8:
                    if src_pos >= src_len:
                        raise EOFError
                    bit_buffer = (bit_buffer << 8) | src[src_pos]
                    src_pos += 1
                    bit_count += 8
                bit_count -= 8
                length = (bit_buffer >> bit_count) & 0xFF
                bit_buffer &= (1 << bit_count) - 1

            length = (length + delta + 3) & 0xFFFFFFFF

            if offset == 0 or offset > cursor:
                raise ValueError(
                    f'Invalid back-reference: offset={offset}, output_size={cursor}')
            start = cursor - offset

            # Back-reference copy using C-level memory operations.
            # When offset >= length, the source and destination regions do not
            # overlap, so we can use a single memcpy. When they do overlap
            # (offset < length), we copy in offset-sized chunks, which is
            # correct because each chunk only references already-written data.
            copy_src = start
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

        return bytearray(out_buf[:size])
    finally:
        free(out_buf)


def a3x_decrypt_current(data, uint32_t key):
    cdef:
        uint32_t t[17]
        int a = 16
        int b = 6
        int i
        uint32_t r, x, y
        const uint8_t[::1] dv = memoryview(data)
        int n = len(data)
        bytearray output = bytearray(n)
        uint8_t[::1] ov = output

    for i in range(17):
        key = (1 - key * <uint32_t>0x53A9B4FB) & 0xFFFFFFFF
        t[i] = key

    # reverse t[0..16]
    for i in range(8):
        x = t[i]
        t[i] = t[16 - i]
        t[16 - i] = x

    for i in range(9):
        r = (_rotl32(t[a], 9) + _rotl32(t[b], 13)) & 0xFFFFFFFF
        t[a] = r
        a = (a + 1) % 17
        b = (b + 1) % 17

    for i in range(n):
        x = t[a]
        y = t[b]
        t[a] = (_rotl32(x, 9) + _rotl32(y, 13)) & 0xFFFFFFFF
        a = (a + 1) % 17
        b = (b + 1) % 17
        x = t[a]
        y = t[b]
        r = (_rotl32(x, 9) + _rotl32(y, 13)) & 0xFFFFFFFF
        t[a] = r
        a = (a + 1) % 17
        b = (b + 1) % 17
        ov[i] = (r >> 24) ^ dv[i]

    return output


def a3x_decrypt_legacy(data, uint32_t key):
    cdef:
        uint32_t *t = <uint32_t *>malloc(624 * sizeof(uint32_t))
        int a = 1
        int b = 0
        int i
        uint32_t x, y
        const uint8_t[::1] dv = memoryview(data)
        int n = len(data)
        bytearray output = bytearray(n)
        uint8_t[::1] ov = output

    if t == NULL:
        raise MemoryError

    try:
        t[0] = key
        for i in range(1, 624):
            key = ((((key ^ (key >> 30)) * <uint32_t>0x6C078965) & 0xFFFFFFFF) + <uint32_t>i) & 0xFFFFFFFF
            t[i] = key

        for i in range(n):
            a -= 1
            b += 1
            if a == 0:
                a = 0x270
                b = 0
                _refactor_state(t)
            x = t[b]
            x = x ^ (x >> 11)
            y = ((x & <uint32_t>0xFF3A58AD) << 7) & 0xFFFFFFFF
            x ^= y
            y = ((x & <uint32_t>0xFFFFDF8C) << 15) & 0xFFFFFFFF
            x ^= y
            y = x ^ (x >> 18)
            ov[i] = ((y >> 1) ^ dv[i]) & 0xFF

        return output
    finally:
        free(t)


cdef void _refactor_state(uint32_t *t) noexcept nogil:
    cdef:
        int i
        uint32_t x, y

    for i in range(0, 0xE3):
        x = t[i] ^ t[i + 1]
        x &= 0x7FFFFFFE
        x ^= t[i]
        x >>= 1
        if t[i + 1] & 1:
            y = <uint32_t>0x9908B0DF
        else:
            y = 0
        x ^= y
        x ^= t[i + 397]
        t[i] = x

    for i in range(0xE3, 0x26F):
        x = t[i] ^ t[i + 1]
        x &= 0x7FFFFFFE
        x ^= t[i]
        x >>= 1
        if t[i + 1] & 1:
            y = <uint32_t>0x9908B0DF
        else:
            y = 0
        x ^= y
        x ^= t[i - 227]
        t[i] = x

    x = t[0]
    y = t[0x26F] ^ x
    y &= 0x7FFFFFFE
    y ^= t[0x26F]
    y >>= 1
    if x & 1:
        x = <uint32_t>0x9908B0DF
    else:
        x = 0
    y ^= x
    y ^= t[0x26F - 227]
    t[0x26F] = y


def a3x_decrypt(data, uint32_t key, bint is_current=True):
    if is_current:
        return a3x_decrypt_current(data, key)
    return a3x_decrypt_legacy(data, key)
