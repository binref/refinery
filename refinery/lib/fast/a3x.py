from __future__ import annotations


def a3x_decompress(data: bytearray | memoryview, is_current: bool) -> bytearray:
    view = memoryview(data)
    size = int.from_bytes(view[4:8], 'big')
    src = bytes(view[8:])
    src_len = len(src)
    src_pos = 0
    bit_buffer = 0
    bit_count = 0
    output = bytearray()

    def _bits(n: int) -> int:
        nonlocal src_pos, bit_buffer, bit_count
        while bit_count < n:
            if src_pos >= src_len:
                raise EOFError
            bit_buffer = (bit_buffer << 8) | src[src_pos]
            src_pos += 1
            bit_count += 8
        bit_count -= n
        result = (bit_buffer >> bit_count) & ((1 << n) - 1)
        bit_buffer &= (1 << bit_count) - 1
        return result

    cursor = 0
    while cursor < size:
        check = _bits(1)
        if check == is_current:
            output.append(_bits(8))
            cursor += 1
            continue
        offset = _bits(15)
        length = _bits(2)
        delta = 0
        if length == 0b11:
            delta = 0x003
            length = _bits(3)
            if length == 0b111:
                delta = 0x00A
                length = _bits(5)
                if length == 0b11111:
                    delta = 0x029
                    length = _bits(8)
                    if length == 0b11111111:
                        delta = 0x128
                        length = _bits(8)
        while length == 0b11111111:
            delta += 0xFF
            length = _bits(8)
        length += delta + 3
        length &= 0xFFFFFFFF
        # replay: copy `length` bytes from `offset` bytes back in the output
        out_len = len(output)
        start = out_len - offset
        if offset <= 0 or start < 0:
            raise ValueError(
                F'Invalid back-reference: offset={offset}, output_size={out_len}')
        rep, r = divmod(length, offset)
        chunk = bytes(output[start:out_len])
        if rep > 0:
            output.extend(chunk * rep)
        if r > 0:
            output.extend(chunk[:r])
        cursor += length

    return output


def a3x_decrypt_current(data: memoryview | bytearray, key: int) -> bytearray:
    a, b, t = 16, 6, []

    for _ in range(17):
        key = 1 - key * 0x53A9B4FB & 0xFFFFFFFF
        t.append(key)

    t.reverse()

    for _ in range(9):
        r = (t[a] << 9 | t[a] >> 23) + (t[b] << 13 | t[b] >> 19) & 0xFFFFFFFF
        t[a] = r
        a = (a + 1) % 17
        b = (b + 1) % 17

    def _decrypted():
        nonlocal a, b
        for v in data:
            x = t[a]
            y = t[b]
            t[a] = (x << 9 | x >> 23) + (y << 13 | y >> 19) & 0xFFFFFFFF
            a = (a + 1) % 17
            b = (b + 1) % 17
            x = t[a]
            y = t[b]
            r = (x << 9 | x >> 23) + (y << 13 | y >> 19) & 0xFFFFFFFF
            t[a] = r
            a = (a + 1) % 17
            b = (b + 1) % 17
            yield (r >> 24) ^ v

    return bytearray(_decrypted())


def a3x_decrypt_legacy(data: bytearray | memoryview, key: int) -> bytearray:
    a, b, t = 1, 0, []

    t.append(key)
    for i in range(1, 624):
        key = ((((key ^ key >> 30) * 0x6C078965) & 0xFFFFFFFF) + i) & 0xFFFFFFFF
        t.append(key)

    def _refactor_state():
        for i in range(0, 0xe3):
            x = t[i] ^ t[i + 1]
            x &= 0x7FFFFFFE
            x ^= t[i]
            x >>= 1
            y = 0x9908B0DF
            if (t[i + 1] % 2 == 0):
                y = 0
            x ^= y
            x ^= t[i + 397]
            t[i] = x

        for i in range(0xe3, 0x18c + 0xe3):
            x = t[i] ^ t[i + 1]
            x &= 0x7FFFFFFE
            x ^= t[i]
            x >>= 1
            y = 0x9908B0DF
            if (t[i + 1] % 2 == 0):
                y = 0
            x ^= y
            x ^= t[i - 227]
            t[i] = x

        x = t[0]
        y = t[0x18c + 0xe3] ^ x
        y &= 0x7FFFFFFE
        y ^= t[0x18c + 0xe3]
        y >>= 1
        if (x % 2 == 1):
            x = 0x9908B0DF
        else:
            x = 0
        y ^= x
        y ^= t[0x18c + 0xe3 - 227]
        t[0x18c + 0xe3] = y

    def _decrypted():
        nonlocal a, b
        for v in data:
            a -= 1
            b += 1
            if a == 0:
                a = 0x270
                b = 0
                _refactor_state()
            x = t[b]
            x = x ^ x >> 11
            y = ((x & 0xFF3A58AD) << 7) & 0xFFFFFFFF
            x ^= y
            y = ((x & 0xFFFFDF8C) << 15) & 0xFFFFFFFF
            x ^= y
            y = x ^ x >> 0x12
            yield ((y >> 1) ^ v) & 0xFF

    return bytearray(_decrypted())


def a3x_decrypt(data: memoryview | bytearray, key: int, is_current: bool = True) -> bytearray:
    if is_current:
        return a3x_decrypt_current(data, key)
    return a3x_decrypt_legacy(data, key)
