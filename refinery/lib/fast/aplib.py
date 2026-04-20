from __future__ import annotations


def _lengthdelta(offset: int) -> int:
    if offset < 0x80 or 0x7D00 <= offset:
        return 2
    elif 0x500 <= offset:
        return 1
    return 0


def _find_longest_match(data: bytes | bytearray, offset: int) -> tuple[int, int]:
    pivot = 0
    limit = size = len(data) - offset
    rewind = 0
    while size > 0:
        pos = data.rfind(data[offset:offset + pivot + size], 0, offset)
        if pos == -1:
            size //= 2
            continue
        rewind = offset - pos
        if pivot + size >= limit:
            return rewind, limit
        else:
            pivot += size
    if not pivot:
        return (0, 0)
    return (rewind, pivot)


def aplib_decompress(data: bytes | bytearray | memoryview) -> bytearray:
    src = bytes(data)
    pos = 0
    end = len(src)
    bitcount = 0
    bitbuffer = 0
    output = bytearray()

    def _read_byte() -> int:
        nonlocal pos
        if pos >= end:
            raise EOFError
        b = src[pos]
        pos += 1
        return b

    def _read_bit() -> int:
        nonlocal bitcount, bitbuffer
        if bitcount == 0:
            bitbuffer = _read_byte()
            bitcount = 8
        bitcount -= 1
        bit = (bitbuffer >> 7) & 1
        bitbuffer = (bitbuffer << 1) & 0xFF
        return bit

    def _read_gamma() -> int:
        result = 1
        result = (result << 1) | _read_bit()
        while _read_bit():
            result = (result << 1) | _read_bit()
        return result

    def _back_copy(offset: int, length: int) -> None:
        for _ in range(length):
            output.append(output[-offset])

    output.append(_read_byte())
    LWM = 0
    R0 = 0

    while True:
        if _read_bit():
            if _read_bit():
                if _read_bit():
                    offs = 0
                    for _ in range(4):
                        offs = (offs << 1) | _read_bit()
                    if offs:
                        _back_copy(offs, 1)
                    else:
                        output.append(0)
                    LWM = 0
                else:
                    b = _read_byte()
                    if b <= 1:
                        break
                    length = 2 + (b & 1)
                    offs = b >> 1
                    _back_copy(offs, length)
                    R0 = offs
                    LWM = 1
            else:
                offs = _read_gamma()
                if LWM == 0 and offs == 2:
                    offs = R0
                    length = _read_gamma()
                    _back_copy(offs, length)
                else:
                    if LWM == 0:
                        offs -= 3
                    else:
                        offs -= 2
                    offs = (offs << 8) | _read_byte()
                    length = _read_gamma()
                    length += _lengthdelta(offs)
                    _back_copy(offs, length)
                    R0 = offs
                LWM = 1
        else:
            output.append(_read_byte())
            LWM = 0

    return output


def aplib_compress(data: bytes | bytearray | memoryview) -> bytearray:
    src = bytes(data)
    length = len(src)
    output = bytearray()
    bitbuffer = 0
    bitcount = 0
    tagoffset = 0
    is_tagged = False

    def _flush_tag() -> None:
        output[tagoffset] = bitbuffer

    def _write_bit(value: int) -> None:
        nonlocal bitcount, bitbuffer, tagoffset, is_tagged
        if bitcount != 0:
            bitcount -= 1
        else:
            if not is_tagged:
                is_tagged = True
            else:
                _flush_tag()
            tagoffset = len(output)
            output.append(0)
            bitcount = 7
            bitbuffer = 0
        if value:
            bitbuffer |= (1 << bitcount)

    def _write_byte(b: int) -> None:
        output.append(b & 0xFF)

    def _write_fixednumber(value: int, nbbit: int) -> None:
        for i in range(nbbit - 1, -1, -1):
            _write_bit((value >> i) & 1)

    def _write_gamma(value: int) -> None:
        length = value.bit_length() - 2
        _write_bit(value & (1 << length))
        for i in range(length - 1, -1, -1):
            _write_bit(1)
            _write_bit(value & (1 << i))
        _write_bit(0)

    offset = 0
    lastoffset = 0
    pair = True

    _write_byte(src[offset])
    offset += 1

    while offset < length:
        match_offset, match_length = _find_longest_match(src, offset)
        if match_length == 0:
            c = src[offset]
            if c == 0:
                _write_bit(1)
                _write_bit(1)
                _write_bit(1)
                _write_fixednumber(0, 4)
                offset += 1
                pair = True
            else:
                _write_bit(0)
                _write_byte(src[offset])
                offset += 1
                pair = True
        elif match_length == 1 and 0 <= match_offset < 16:
            _write_bit(1)
            _write_bit(1)
            _write_bit(1)
            _write_fixednumber(match_offset, 4)
            offset += 1
            pair = True
        elif 2 <= match_length <= 3 and 0 < match_offset <= 127:
            _write_bit(1)
            _write_bit(1)
            _write_bit(0)
            b = (match_offset << 1) + (match_length - 2)
            _write_byte(b)
            offset += match_length
            lastoffset = match_offset
            pair = False
        elif 3 < match_length and 2 <= match_offset:
            _write_bit(1)
            _write_bit(0)
            if pair and lastoffset == match_offset:
                _write_gamma(2)
                _write_gamma(match_length)
            else:
                high = (match_offset >> 8) + 2
                if pair:
                    high += 1
                _write_gamma(high)
                _write_byte(match_offset & 0xFF)
                _write_gamma(match_length - _lengthdelta(match_offset))
            offset += match_length
            lastoffset = match_offset
            pair = False
        else:
            _write_bit(0)
            _write_byte(src[offset])
            offset += 1
            pair = True

    _write_bit(1)
    _write_bit(1)
    _write_bit(0)
    _write_byte(0)

    _flush_tag()
    return output
