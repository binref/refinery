from __future__ import annotations

from refinery.lib.qr.correct import rs_correct
from refinery.lib.qr.tables import (
    ALIGNMENT_POSITIONS,
    ALPHANUMERIC_CHARSET,
    EC_PARAMETERS,
    FORMAT_INFO_STRINGS,
    MASK_FUNCTIONS,
    VERSION_INFO_STRINGS,
    ECLevel,
    char_count_bits,
    version_size,
)


def _hamming_distance(a: int, b: int) -> int:
    x = a ^ b
    count = 0
    while x:
        count += x & 1
        x >>= 1
    return count


def read_format_info(modules: list[list[bool]]) -> tuple[ECLevel, int]:
    size = len(modules)
    bits1 = 0
    for i in range(6):
        if modules[8][i]:
            bits1 |= 1 << (14 - i)
    if modules[8][7]:
        bits1 |= 1 << 8
    if modules[8][8]:
        bits1 |= 1 << 7
    if modules[7][8]:
        bits1 |= 1 << 6
    for i in range(6):
        if modules[5 - i][8]:
            bits1 |= 1 << (5 - i)

    bits2 = 0
    for i in range(7):
        if modules[size - 1 - i][8]:
            bits2 |= 1 << (14 - i)
    for i in range(8):
        if modules[8][size - 8 + i]:
            bits2 |= 1 << (7 - i)

    for bits in (bits1, bits2):
        best_match = -1
        best_dist = 15
        for idx, candidate in enumerate(FORMAT_INFO_STRINGS):
            dist = _hamming_distance(bits, candidate)
            if dist < best_dist:
                best_dist = dist
                best_match = idx
        if best_dist <= 3 and best_match >= 0:
            raw_ec = best_match >> 3
            ec_level = ECLevel([1, 0, 3, 2][raw_ec])
            mask_pattern = best_match & 0x07
            return ec_level, mask_pattern

    raise ValueError('unable to read format information')


def read_version_info(modules: list[list[bool]], size: int) -> int:
    version_from_size = (size - 17) // 4
    if version_from_size < 7:
        return version_from_size

    bits1 = 0
    for i in range(6):
        for j in range(3):
            if modules[i][size - 11 + j]:
                bits1 |= 1 << (i * 3 + j)

    bits2 = 0
    for j in range(6):
        for i in range(3):
            if modules[size - 11 + i][j]:
                bits2 |= 1 << (j * 3 + i)

    for bits in (bits1, bits2):
        best_version = -1
        best_dist = 18
        for ver, code in VERSION_INFO_STRINGS.items():
            dist = _hamming_distance(bits, code)
            if dist < best_dist:
                best_dist = dist
                best_version = ver
        if best_dist <= 3 and best_version >= 7:
            return best_version

    return version_from_size


def _build_function_pattern_mask(
    version: int, size: int,
) -> list[list[bool]]:
    mask = [[False] * size for _ in range(size)]
    for r in range(8):
        for c in range(8):
            mask[r][c] = True
    for r in range(8):
        for c in range(8):
            mask[r][size - 8 + c] = True
    for r in range(8):
        for c in range(8):
            mask[size - 8 + r][c] = True
    for i in range(size):
        mask[6][i] = True
        mask[i][6] = True
    mask[size - 8][8] = True
    for i in range(9):
        mask[8][i] = True
        mask[i][8] = True
    for i in range(8):
        mask[8][size - 8 + i] = True
        mask[size - 8 + i][8] = True
    if version >= 2:
        positions = ALIGNMENT_POSITIONS[version]
        for r in positions:
            for c in positions:
                if mask[r - 2][c - 2] or mask[r - 2][c + 2]:
                    continue
                if mask[r + 2][c - 2] or mask[r + 2][c + 2]:
                    continue
                for dr in range(-2, 3):
                    for dc in range(-2, 3):
                        mask[r + dr][c + dc] = True
    if version >= 7:
        for i in range(6):
            for j in range(3):
                mask[i][size - 11 + j] = True
                mask[size - 11 + j][i] = True
    return mask


def _unmask(
    modules: list[list[bool]],
    mask_pattern: int,
    function_mask: list[list[bool]],
) -> list[list[bool]]:
    size = len(modules)
    mask_fn = MASK_FUNCTIONS[mask_pattern]
    result = [row[:] for row in modules]
    for r in range(size):
        for c in range(size):
            if not function_mask[r][c] and mask_fn(r, c):
                result[r][c] = not result[r][c]
    return result


def _read_data_bits(
    modules: list[list[bool]],
    function_mask: list[list[bool]],
    size: int,
) -> bytearray:
    bits: list[bool] = []
    col = size - 1
    while col >= 0:
        if col == 6:
            col -= 1
        going_up = ((size - 1 - col) // 2) % 2 == 0
        rows = range(size - 1, -1, -1) if going_up else range(size)
        for row in rows:
            for dc in (0, -1):
                c = col + dc
                if c < 0:
                    continue
                if not function_mask[row][c]:
                    bits.append(modules[row][c])
        col -= 2
    result = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for j in range(8):
            if bits[i + j]:
                byte |= 1 << (7 - j)
        result.append(byte)
    return result


def _deinterleave_blocks(
    data: bytearray, version: int, ec_level: ECLevel,
) -> list[bytearray]:
    params = EC_PARAMETERS[(version, ec_level)]
    blocks: list[bytearray] = []
    g1_total = params.group1_data_cw + params.ec_per_block
    g2_total = params.group2_data_cw + params.ec_per_block
    for _ in range(params.group1_blocks):
        blocks.append(bytearray(g1_total))
    for _ in range(params.group2_blocks):
        blocks.append(bytearray(g2_total))
    total_blocks = params.group1_blocks + params.group2_blocks
    max_data_cw = max(
        params.group1_data_cw,
        params.group2_data_cw if params.group2_blocks else 0,
    )
    idx = 0
    for i in range(max_data_cw):
        for b in range(total_blocks):
            data_cw = (
                params.group1_data_cw if b < params.group1_blocks
                else params.group2_data_cw
            )
            if i < data_cw:
                if idx < len(data):
                    blocks[b][i] = data[idx]
                idx += 1
    for i in range(params.ec_per_block):
        for b in range(total_blocks):
            data_cw = (
                params.group1_data_cw if b < params.group1_blocks
                else params.group2_data_cw
            )
            if idx < len(data):
                blocks[b][data_cw + i] = data[idx]
            idx += 1
    return blocks


def _error_correct_blocks(
    blocks: list[bytearray],
    version: int,
    ec_level: ECLevel,
) -> bytearray:
    params = EC_PARAMETERS[(version, ec_level)]
    corrected = bytearray()
    for i, block in enumerate(blocks):
        try:
            corrected_block = rs_correct(block, params.ec_per_block)
        except ValueError:
            data_cw = (
                params.group1_data_cw if i < params.group1_blocks
                else params.group2_data_cw
            )
            corrected_block = bytearray(block[:data_cw])
        corrected.extend(corrected_block)
    return corrected


class _BitStream:
    def __init__(self, data: bytearray):
        self._data = data
        self._pos = 0

    def read(self, n: int) -> int:
        result = 0
        for _ in range(n):
            byte_idx = self._pos >> 3
            bit_idx = 7 - (self._pos & 7)
            if byte_idx < len(self._data):
                if self._data[byte_idx] & (1 << bit_idx):
                    result = (result << 1) | 1
                else:
                    result <<= 1
            else:
                result <<= 1
            self._pos += 1
        return result

    @property
    def remaining(self) -> int:
        return max(0, len(self._data) * 8 - self._pos)


def _parse_bitstream(data: bytearray, version: int) -> bytes:
    stream = _BitStream(data)
    result = bytearray()
    while stream.remaining >= 4:
        mode = stream.read(4)
        if mode == 0:
            break
        elif mode == 0b0001:
            _decode_numeric(stream, version, result)
        elif mode == 0b0010:
            _decode_alphanumeric(stream, version, result)
        elif mode == 0b0100:
            _decode_byte(stream, version, result)
        elif mode == 0b1000:
            _decode_kanji(stream, version, result)
        elif mode == 0b0111:
            _decode_eci(stream)
        else:
            break
    return bytes(result)


def _decode_numeric(
    stream: _BitStream, version: int, result: bytearray,
) -> None:
    count = stream.read(char_count_bits('numeric', version))
    while count >= 3:
        triplet = stream.read(10)
        result.extend(F'{triplet:03d}'.encode('ascii'))
        count -= 3
    if count == 2:
        pair = stream.read(7)
        result.extend(F'{pair:02d}'.encode('ascii'))
    elif count == 1:
        digit = stream.read(4)
        result.extend(F'{digit:01d}'.encode('ascii'))


def _decode_alphanumeric(
    stream: _BitStream, version: int, result: bytearray,
) -> None:
    count = stream.read(char_count_bits('alphanumeric', version))
    charset = ALPHANUMERIC_CHARSET
    while count >= 2:
        pair = stream.read(11)
        c1 = pair // 45
        c2 = pair % 45
        result.append(ord(charset[c1]))
        result.append(ord(charset[c2]))
        count -= 2
    if count == 1:
        val = stream.read(6)
        result.append(ord(charset[val]))


def _decode_byte(
    stream: _BitStream, version: int, result: bytearray,
) -> None:
    count = stream.read(char_count_bits('byte', version))
    for _ in range(count):
        result.append(stream.read(8))


def _decode_kanji(
    stream: _BitStream, version: int, result: bytearray,
) -> None:
    count = stream.read(char_count_bits('kanji', version))
    for _ in range(count):
        val = stream.read(13)
        high = val // 0xC0
        low = val % 0xC0
        code = (high << 8) | low
        if code <= 0x1F3F:
            code += 0x8140
        else:
            code += 0xC140
        result.extend(code.to_bytes(2, 'big'))


def _decode_eci(stream: _BitStream) -> None:
    first = stream.read(8)
    if first & 0x80 == 0:
        pass
    elif first & 0xC0 == 0x80:
        stream.read(8)
    elif first & 0xE0 == 0xC0:
        stream.read(16)


def decode_qr_grid(modules: list[list[bool]], version: int) -> bytes:
    size = len(modules)
    actual_version = read_version_info(modules, size)
    if actual_version != version:
        version = actual_version
        size = version_size(version)
    ec_level, mask_pattern = read_format_info(modules)
    function_mask = _build_function_pattern_mask(version, size)
    unmasked = _unmask(modules, mask_pattern, function_mask)
    raw_data = _read_data_bits(unmasked, function_mask, size)
    blocks = _deinterleave_blocks(raw_data, version, ec_level)
    corrected = _error_correct_blocks(blocks, version, ec_level)
    return _parse_bitstream(corrected, version)
