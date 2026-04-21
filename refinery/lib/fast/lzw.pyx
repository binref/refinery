# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True
cimport cython

from libc.stdint cimport uint8_t, uint16_t, uint32_t
from libc.stdlib cimport free, malloc, realloc
from libc.string cimport memset

DEF INIT_BITS = 9
DEF BITS = 0x10
DEF CLEAR = 0x100
DEF FIRST = 0x101
DEF WSIZE = 0x8000

from refinery.lib.exceptions import RefineryPartialResult


cdef int _ensure_capacity(
    uint8_t **buf, uint32_t *cap, uint32_t needed
) except -1 nogil:
    cdef uint32_t new_cap
    cdef uint8_t *tmp
    if needed <= cap[0]:
        return 0
    new_cap = cap[0]
    while new_cap < needed:
        new_cap = new_cap * 2
    tmp = <uint8_t *>realloc(buf[0], new_cap)
    if tmp == NULL:
        with gil:
            raise MemoryError
    buf[0] = tmp
    cap[0] = new_cap
    return 0


def lzw_decompress(data, int maxbits, bint block_mode) -> bytearray:
    cdef:
        const uint8_t[::1] src_view = memoryview(data)
        const uint8_t *src
        int src_len
        uint8_t *out_buf
        uint32_t out_cap, out_len
        uint8_t tab_suffix[WSIZE * 2]
        uint16_t tab_prefix[1 << BITS]
        int n_bits, maxcode, bitmask, maxmaxcode
        int oldcode, finchar, posbits, inbits
        int free_entry
        bint resetbuf
        int code, incode
        int n, p_int
        uint32_t b0, b1, b2
        uint8_t stack_buf[WSIZE]
        int stack_len
        int i

    if maxbits > BITS:
        raise ValueError(F'Compressed with {maxbits} bits; cannot handle file.')

    src = &src_view[0]
    src_len = len(src_view)
    maxmaxcode = 1 << maxbits

    memset(tab_suffix, 0, WSIZE * 2)
    memset(tab_prefix, 0, (1 << BITS) * sizeof(uint16_t))
    for i in range(256):
        tab_suffix[i] = <uint8_t>i

    n_bits = INIT_BITS
    maxcode = (1 << n_bits) - 1
    bitmask = (1 << n_bits) - 1
    oldcode = -1
    finchar = 0
    posbits = 0

    free_entry = FIRST if block_mode else 0x100

    out_cap = <uint32_t>(src_len * 3) if src_len < 0x20000000 else <uint32_t>src_len
    if out_cap < 256:
        out_cap = 256
    out_buf = <uint8_t *>malloc(out_cap)
    if out_buf == NULL:
        raise MemoryError
    out_len = 0

    try:
        resetbuf = True
        while resetbuf:
            resetbuf = False

            src = src + (posbits >> 3)
            src_len = src_len - (posbits >> 3)
            posbits = 0
            inbits = (src_len << 3) - (n_bits - 1)

            while inbits > posbits:
                if free_entry > maxcode:
                    n = n_bits << 3
                    p_int = posbits - 1
                    posbits = p_int + (n - (p_int + n) % n)
                    n_bits += 1
                    if n_bits == maxbits:
                        maxcode = maxmaxcode
                    else:
                        maxcode = (1 << n_bits) - 1
                    bitmask = (1 << n_bits) - 1
                    resetbuf = True
                    break

                i = posbits >> 3
                if i + 2 < src_len:
                    b0 = <uint32_t>src[i]
                    b1 = <uint32_t>src[i + 1]
                    b2 = <uint32_t>src[i + 2]
                elif i + 1 < src_len:
                    b0 = <uint32_t>src[i]
                    b1 = <uint32_t>src[i + 1]
                    b2 = 0
                elif i < src_len:
                    b0 = <uint32_t>src[i]
                    b1 = 0
                    b2 = 0
                else:
                    break
                code = <int>((b0 | (b1 << 8) | (b2 << 16)) >> (posbits & 7)) & bitmask
                posbits += n_bits

                if oldcode == -1:
                    if code >= 256:
                        raise ValueError('corrupt input.')
                    oldcode = code
                    finchar = oldcode
                    _ensure_capacity(&out_buf, &out_cap, out_len + 1)
                    out_buf[out_len] = <uint8_t>finchar
                    out_len += 1
                    continue

                if code == CLEAR and block_mode:
                    memset(tab_prefix, 0, 0x100 * sizeof(uint16_t))
                    free_entry = FIRST - 1
                    n = n_bits << 3
                    p_int = posbits - 1
                    posbits = p_int + (n - (p_int + n) % n)
                    n_bits = INIT_BITS
                    maxcode = (1 << n_bits) - 1
                    bitmask = (1 << n_bits) - 1
                    resetbuf = True
                    break

                incode = code
                stack_len = 0

                if code >= free_entry:
                    if code > free_entry:
                        raise RefineryPartialResult('corrupt input.', bytearray(out_buf[:out_len]))
                    stack_buf[stack_len] = <uint8_t>finchar
                    stack_len += 1
                    code = oldcode
                while code >= 256:
                    stack_buf[stack_len] = tab_suffix[code]
                    stack_len += 1
                    code = <int>tab_prefix[code]

                finchar = <int>tab_suffix[code]
                stack_buf[stack_len] = <uint8_t>finchar
                stack_len += 1

                _ensure_capacity(&out_buf, &out_cap, out_len + <uint32_t>stack_len)
                for i in range(stack_len - 1, -1, -1):
                    out_buf[out_len] = stack_buf[i]
                    out_len += 1

                code = free_entry
                if code < maxmaxcode:
                    tab_prefix[code] = <uint16_t>(oldcode & 0xFFFF)
                    tab_suffix[code] = <uint8_t>(finchar & 0xFF)
                    free_entry = code + 1

                oldcode = incode

        return bytearray(out_buf[:out_len])
    finally:
        free(out_buf)
