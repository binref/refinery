# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True
cimport cython

from libc.stdint cimport uint8_t, uint32_t, uint64_t
from libc.stdlib cimport free, malloc
from libc.string cimport memcpy

from refinery.lib.fast._buffer cimport reserve

from refinery.lib.exceptions import RefineryPartialResult


cdef inline uint32_t _lengthdelta(uint64_t offset) noexcept nogil:
    if offset < 0x80 or offset >= 0x7D00:
        return 2
    elif offset >= 0x500:
        return 1
    return 0


cdef struct BitReader:
    const uint8_t *src
    Py_ssize_t end
    Py_ssize_t pos
    uint32_t tag
    uint32_t bitcount


cdef struct Output:
    uint8_t *buf
    Py_ssize_t cap
    Py_ssize_t size


cdef inline uint32_t _read_byte(BitReader *r) noexcept nogil:
    """
    Read the next byte, or zero past the end of the input; reading past the end moves the position
    after the end.
    """
    if r.pos >= r.end:
        r.pos = r.end + 1
        return 0
    r.pos += 1
    return r.src[r.pos - 1]


cdef inline uint32_t _read_bit(BitReader *r) noexcept nogil:
    cdef uint32_t bit
    if r.bitcount == 0:
        r.tag = _read_byte(r)
        r.bitcount = 8
    r.bitcount -= 1
    bit = (r.tag >> 7) & 1
    r.tag = (r.tag << 1) & 0xFF
    return bit


cdef inline uint32_t _read_gamma(BitReader *r) noexcept nogil:
    cdef uint32_t result = 1
    result = (result << 1) | _read_bit(r)
    while _read_bit(r):
        result = (result << 1) | _read_bit(r)
    return result


cdef inline int _put(Output *out, uint8_t b) except -1 nogil:
    reserve(&out.buf, &out.cap, out.size, 1)
    out.buf[out.size] = b
    out.size += 1
    return 0


cdef int _offset_error(uint64_t offset, Py_ssize_t size) except -1:
    raise ValueError(F'aPLib match offset {offset} is outside the output of size {size}')


cdef inline int _back_copy(Output *out, uint64_t offset, uint32_t length) except -1 nogil:
    cdef uint32_t i
    cdef uint8_t *dst
    if offset == 0 or offset > <uint64_t>out.size:
        with gil:
            _offset_error(offset, out.size)
    reserve(&out.buf, &out.cap, out.size, length)
    dst = out.buf + out.size
    for i in range(length):
        dst[i] = dst[<Py_ssize_t>i - <Py_ssize_t>offset]
    out.size += length
    return 0


def aplib_decompress(data) -> bytearray:
    """
    Decompress an aPLib stream. Input that ends before the end marker, or that cannot be decoded
    after some output, raises a `RefineryPartialResult` with the output decoded so far.
    """
    cdef:
        const uint8_t[::1] src = memoryview(data)
        BitReader r
        Output out
        uint64_t offs
        uint64_t R0 = 0
        uint32_t length, b
        bint LWM = 0
        int i

    if len(src) == 0:
        return bytearray()

    r.src = &src[0]
    r.end = len(src)
    r.pos = 0
    r.tag = 0
    r.bitcount = 0
    out.cap = r.end * 4 if r.end < 0x10000000 else r.end
    if out.cap < 256:
        out.cap = 256
    out.size = 0
    out.buf = <uint8_t *>malloc(out.cap)
    if out.buf == NULL:
        raise MemoryError

    try:
        _put(&out, _read_byte(&r))
        while True:
            if not _read_bit(&r):
                b = _read_byte(&r)
                if r.pos > r.end:
                    break
                _put(&out, b)
                LWM = 0
            elif not _read_bit(&r):
                offs = _read_gamma(&r)
                if not LWM and offs == 2:
                    offs = R0
                    length = _read_gamma(&r)
                else:
                    offs = ((offs - (2 if LWM else 3)) << 8) | _read_byte(&r)
                    length = _read_gamma(&r) + _lengthdelta(offs)
                if r.pos > r.end:
                    break
                _back_copy(&out, offs, length)
                R0 = offs
                LWM = 1
            elif not _read_bit(&r):
                b = _read_byte(&r)
                if r.pos > r.end or b <= 1:
                    break
                offs = b >> 1
                _back_copy(&out, offs, 2 + (b & 1))
                R0 = offs
                LWM = 1
            else:
                offs = 0
                for i in range(4):
                    offs = (offs << 1) | _read_bit(&r)
                if r.pos > r.end:
                    break
                if offs:
                    _back_copy(&out, offs, 1)
                else:
                    _put(&out, 0)
                LWM = 0
        if r.pos > r.end:
            raise RefineryPartialResult(
                'The input ended before the end marker.', bytearray(out.buf[:out.size])
            )
        return bytearray(out.buf[:out.size])
    except RefineryPartialResult:
        raise
    except ValueError as error:
        raise RefineryPartialResult(
            F'Decoding failed after {out.size} bytes: {error!s}', bytearray(out.buf[:out.size])
        ) from error
    finally:
        free(out.buf)


cdef struct CompressorState:
    const uint8_t *src
    uint32_t length
    uint8_t *out_buf
    Py_ssize_t out_cap
    Py_ssize_t cursor
    uint8_t bitbuffer
    uint32_t bitcount
    Py_ssize_t tagoffset
    int is_tagged
    uint32_t offset
    uint32_t lastoffset
    int pair


cdef inline void _flush_tag(CompressorState *st) noexcept nogil:
    st.out_buf[st.tagoffset] = st.bitbuffer


cdef int _write_bit(CompressorState *st, int value) except -1 nogil:
    if st.bitcount != 0:
        st.bitcount -= 1
    else:
        if not st.is_tagged:
            st.is_tagged = 1
        else:
            _flush_tag(st)
        reserve(&st.out_buf, &st.out_cap, st.cursor, 1)
        st.tagoffset = st.cursor
        st.out_buf[st.cursor] = 0
        st.cursor += 1
        st.bitcount = 7
        st.bitbuffer = 0
    if value:
        st.bitbuffer |= (1 << st.bitcount)
    return 0


cdef inline int _write_byte(CompressorState *st, uint8_t b) except -1 nogil:
    reserve(&st.out_buf, &st.out_cap, st.cursor, 1)
    st.out_buf[st.cursor] = b
    st.cursor += 1
    return 0


cdef int _write_fixednumber(CompressorState *st, uint32_t value, int nbbit) except -1 nogil:
    cdef int i
    for i in range(nbbit - 1, -1, -1):
        _write_bit(st, (value >> i) & 1)
    return 0


cdef int _write_gamma(CompressorState *st, uint32_t value) except -1 nogil:
    cdef int length, i
    if value < 2:
        return 0
    length = 0
    cdef uint32_t tmp = value >> 2
    while tmp:
        length += 1
        tmp >>= 1
    _write_bit(st, (value >> length) & 1)
    for i in range(length - 1, -1, -1):
        _write_bit(st, 1)
        _write_bit(st, (value >> i) & 1)
    _write_bit(st, 0)
    return 0


cdef (uint32_t, uint32_t) _find_longest_match(
    bytes data, uint32_t offset
):
    cdef:
        uint32_t pivot = 0
        uint32_t total = <uint32_t>len(data)
        uint32_t limit = total - offset
        uint32_t size = limit
        uint32_t rewind = 0
        int pos

    while size > 0:
        pos = data.rfind(data[offset:offset + pivot + size], 0, offset)
        if pos == -1:
            size = size // 2
            continue
        rewind = offset - <uint32_t>pos
        if pivot + size >= limit:
            return (rewind, limit)
        pivot += size
    if pivot == 0:
        return (0, 0)
    return (rewind, pivot)


def aplib_compress(data) -> bytearray:
    cdef:
        bytes src_bytes = bytes(data)
        const uint8_t[::1] src_view = src_bytes
        uint32_t length = <uint32_t>len(data)
        CompressorState st
        uint32_t match_offset, match_length
        uint8_t c
        uint32_t high

    if length == 0:
        return bytearray()

    st.src = &src_view[0]
    st.length = length
    st.out_cap = length if length > 256 else 256
    st.out_buf = <uint8_t *>malloc(st.out_cap)
    if st.out_buf == NULL:
        raise MemoryError
    st.cursor = 0
    st.bitbuffer = 0
    st.bitcount = 0
    st.tagoffset = 0
    st.is_tagged = 0
    st.offset = 0
    st.lastoffset = 0
    st.pair = 1

    try:
        # first byte verbatim
        _write_byte(&st, st.src[st.offset])
        st.offset += 1

        while st.offset < st.length:
            match_offset, match_length = _find_longest_match(
                src_bytes, st.offset
            )

            if match_length == 0:
                c = st.src[st.offset]
                if c == 0:
                    # singlebyte(0)
                    _write_bit(&st, 1)
                    _write_bit(&st, 1)
                    _write_bit(&st, 1)
                    _write_fixednumber(&st, 0, 4)
                    st.offset += 1
                    st.pair = 1
                else:
                    # literal
                    _write_bit(&st, 0)
                    _write_byte(&st, st.src[st.offset])
                    st.offset += 1
                    st.pair = 1
            elif match_length == 1 and match_offset < 16:
                # singlebyte
                _write_bit(&st, 1)
                _write_bit(&st, 1)
                _write_bit(&st, 1)
                _write_fixednumber(&st, match_offset, 4)
                st.offset += 1
                st.pair = 1
            elif 2 <= match_length <= 3 and 0 < match_offset <= 127:
                # shortblock
                _write_bit(&st, 1)
                _write_bit(&st, 1)
                _write_bit(&st, 0)
                _write_byte(&st, <uint8_t>((match_offset << 1) + (match_length - 2)))
                st.offset += match_length
                st.lastoffset = match_offset
                st.pair = 0
            elif match_length > 3 and match_offset >= 2:
                # block
                _write_bit(&st, 1)
                _write_bit(&st, 0)
                if st.pair and st.lastoffset == match_offset:
                    _write_gamma(&st, 2)
                    _write_gamma(&st, match_length)
                else:
                    high = (match_offset >> 8) + 2
                    if st.pair:
                        high += 1
                    _write_gamma(&st, high)
                    _write_byte(&st, <uint8_t>(match_offset & 0xFF))
                    _write_gamma(&st, match_length - _lengthdelta(match_offset))
                st.offset += match_length
                st.lastoffset = match_offset
                st.pair = 0
            else:
                # literal fallback
                _write_bit(&st, 0)
                _write_byte(&st, st.src[st.offset])
                st.offset += 1
                st.pair = 1

        # end marker
        _write_bit(&st, 1)
        _write_bit(&st, 1)
        _write_bit(&st, 0)
        _write_byte(&st, 0)

        _flush_tag(&st)
        return bytearray(st.out_buf[:st.cursor])
    finally:
        free(st.out_buf)
