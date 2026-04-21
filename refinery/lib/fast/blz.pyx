# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True
cimport cython

from libc.stdint cimport uint8_t, uint16_t, uint32_t
from libc.stdlib cimport free, malloc, realloc
from libc.string cimport memcpy


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


cdef inline uint32_t _readbit(
    const uint8_t *src, int end,
    int *pos, uint32_t *bitcount, uint16_t *bitstore,
) except? 0xFFFFFFFF:
    if bitcount[0] == 0:
        if pos[0] + 1 >= end:
            raise EOFError('unexpected end of input during bit read')
        bitstore[0] = <uint16_t>src[pos[0]] | (<uint16_t>src[pos[0] + 1] << 8)
        pos[0] += 2
        bitcount[0] = 15
    else:
        bitcount[0] -= 1
    return (bitstore[0] >> bitcount[0]) & 1


cdef inline uint32_t _readint(
    const uint8_t *src, int end,
    int *pos, uint32_t *bitcount, uint16_t *bitstore,
) except? 0xFFFFFFFF:
    cdef uint32_t result = 2 + _readbit(src, end, pos, bitcount, bitstore)
    while _readbit(src, end, pos, bitcount, bitstore):
        result = (result << 1) | _readbit(src, end, pos, bitcount, bitstore)
    return result


def blz_decompress_chunk(
    data,
    int src_offset,
    int verbatim_offset,
    uint32_t size,
    prefix=None,
) -> tuple:
    """
    Decompress a single BriefLZ chunk.

    Args:
        data: The full source buffer (bytes-like)
        src_offset: Byte offset into data where the compressed bitstream starts
                    (immediately after the verbatim first byte)
        verbatim_offset: Byte offset of the first verbatim byte
        size: Expected decompressed size in bytes
        prefix: Optional bytes-like prefix buffer for cross-chunk back-references.
                Back-references can reach into this buffer.

    Returns:
        (decompressed_bytes, new_src_offset) tuple
    """
    cdef:
        const uint8_t[::1] src = memoryview(data)
        int end = len(data)
        int pos = src_offset
        uint32_t bitcount = 0
        uint16_t bitstore = 0
        uint32_t bit
        uint32_t length, sector, offset, delta
        uint32_t decompressed = 1
        uint32_t cursor = 0
        uint32_t out_cap
        uint8_t *out_buf
        uint32_t prefix_len = 0
        const uint8_t[::1] prefix_view
        uint32_t available, quotient, remainder, copy_len
        uint32_t global_pos, ref_start

    if prefix is not None and len(prefix) > 0:
        prefix_view = memoryview(prefix)
        prefix_len = <uint32_t>len(prefix)

    out_cap = size if size > 256 else 256
    out_buf = <uint8_t *>malloc(out_cap)
    if out_buf == NULL:
        raise MemoryError

    try:
        out_buf[0] = src[verbatim_offset]
        cursor = 1

        while decompressed < size:
            bit = _readbit(&src[0], end, &pos, &bitcount, &bitstore)
            if bit:
                length = _readint(&src[0], end, &pos, &bitcount, &bitstore) + 2
                sector = _readint(&src[0], end, &pos, &bitcount, &bitstore) - 2
                if pos >= end:
                    raise EOFError('unexpected end of input reading offset byte')
                offset = <uint32_t>src[pos] + 1
                pos += 1
                delta = offset + 0x100 * sector
                available = prefix_len + cursor
                if delta > available:
                    raise ValueError(
                        F'Requested rewind by 0x{delta:08X} bytes '
                        F'with only 0x{available:08X} bytes in output buffer.'
                    )
                _ensure_capacity(&out_buf, &out_cap, cursor + length)
                # Perform the replay copy, potentially spanning prefix and output
                global_pos = available - delta
                copy_len = length
                while copy_len > 0:
                    if global_pos < prefix_len:
                        # Reading from prefix
                        ref_start = global_pos
                        chunk_avail = prefix_len - ref_start
                        if chunk_avail > copy_len:
                            chunk_avail = copy_len
                        memcpy(&out_buf[cursor], &prefix_view[ref_start], chunk_avail)
                        cursor += chunk_avail
                        global_pos += chunk_avail
                        copy_len -= chunk_avail
                    else:
                        # Reading from output buffer
                        ref_start = global_pos - prefix_len
                        chunk_avail = cursor - ref_start
                        if chunk_avail > copy_len:
                            chunk_avail = copy_len
                        if chunk_avail == 0:
                            raise ValueError('zero-length copy in replay')
                        # Handle overlapping copy byte-by-byte when needed
                        if ref_start + chunk_avail > cursor:
                            chunk_avail = cursor - ref_start
                        memcpy(&out_buf[cursor], &out_buf[ref_start], chunk_avail)
                        cursor += chunk_avail
                        global_pos += chunk_avail
                        copy_len -= chunk_avail
                decompressed += length
            else:
                if pos >= end:
                    raise EOFError('unexpected end of input reading literal')
                _ensure_capacity(&out_buf, &out_cap, cursor + 1)
                out_buf[cursor] = src[pos]
                pos += 1
                cursor += 1
                decompressed += 1

        result = bytearray(out_buf[:cursor])
        return (result, pos)
    finally:
        free(out_buf)
