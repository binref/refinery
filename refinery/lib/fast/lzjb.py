from __future__ import annotations

_MATCH_LEN = 6
_MATCH_MIN = 3
_MATCH_MAX = (1 << _MATCH_LEN) + (_MATCH_MIN - 1)
_OFFSET_MASK = (1 << (16 - _MATCH_LEN)) - 1
_LEMPEL_SIZE = 0x1000


def lzjb_decompress(data: bytes | bytearray | memoryview) -> bytearray:
    src = memoryview(data)
    end = len(src)
    pos = 0
    dst = bytearray()

    while pos < end:
        copy_byte = src[pos]
        pos += 1

        if copy_byte == 0:
            chunk = src[pos:pos + 8]
            dst.extend(chunk)
            pos += len(chunk)
            continue

        for mask in (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80):
            if pos >= end:
                break
            if not (copy_byte & mask):
                dst.append(src[pos])
                pos += 1
            else:
                if not dst:
                    raise ValueError('copy requested against empty buffer')
                if pos + 1 >= end:
                    break
                pair = (src[pos] << 8) | src[pos + 1]
                pos += 2
                match_len = (pair >> 10) + _MATCH_MIN
                match_pos = pair & 0x3FF
                if match_pos == 0 or match_pos > len(dst):
                    raise RuntimeError('invalid match offset')
                copy_src = len(dst) - match_pos
                while match_len > 0:
                    match = dst[copy_src:copy_src + match_len]
                    dst.extend(match)
                    copy_src += len(match)
                    match_len -= len(match)

    return dst


def lzjb_compress(data: bytes | bytearray | memoryview) -> bytearray:
    src = memoryview(data)
    length = len(src)
    output = bytearray()
    lempel = [0] * _LEMPEL_SIZE
    copymask = 0x80
    position = 0
    copy_map = None

    while position < length:
        copymask <<= 1
        if copymask >= 0x100:
            copymask = 1
            copy_map = len(output)
            output.append(0)
        if position > length - _MATCH_MAX:
            output.append(src[position])
            position += 1
            continue
        hsh = (src[position] << 16) + (src[position + 1] << 8) + src[position + 2]
        hsh += hsh >> 9
        hsh += hsh >> 5
        hsh %= _LEMPEL_SIZE
        offset = (position - lempel[hsh]) & _OFFSET_MASK
        lempel[hsh] = position
        cpy = position - offset
        if cpy >= 0 and cpy != position and src[position:position + 3] == src[cpy:cpy + 3]:
            if copy_map is None:
                raise ValueError
            output[copy_map] |= copymask
            mlen = min(length - position, _MATCH_MAX)
            for mlen in range(_MATCH_MIN, mlen):
                if src[position + mlen] != src[cpy + mlen]:
                    break
            output.append(((mlen - _MATCH_MIN) << (8 - _MATCH_LEN)) | (offset >> 8))
            output.append(offset & 255)
            position += mlen
        else:
            output.append(src[position])
            position += 1

    return output
