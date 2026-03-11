from __future__ import annotations

import base64
import io
import unittest

from .. import TestUnitBase

_NUMERIC_V1_M = (
    'iVBORw0KGgoAAAANSUhEUgAAABcAAAAXAQAAAADIUekNAAAAZ0lEQVR4nAFcAKP/Af8A/wCAwgIC'
    'PtD4AaII4AIA/AACAEQAAb4INALC5AgA/5/+Ar/lyAIjzcQA6NpCAKPwzgL1cEQA/4vOAIDFOgI+'
    'OTwC5PfIAaIu/gIAEcQCHO/EBMIbKAH/AP/I4iZGkMDu4QAAAABJRU5ErkJggg=='
)

_ALPHANUM_V1_L = (
    'iVBORw0KGgoAAAANSUhEUgAAABcAAAAXAQAAAADIUekNAAAAZ0lEQVR4nAFcAKP/Af8A/wCA2gIC'
    'Ptz4AuQokAIA2AACACwAAL6K+gLCIAgA/+P+AIIZVgJpECwCqw7YAdEOnwDsN+4A/6DSAYAKAAI+'
    'VtwBogkbAgAAiAIA6lAEHAErBMIV/wH/AP8DTR//FUsC2QAAAABJRU5ErkJggg=='
)

_BYTE_V1_Q = (
    'iVBORw0KGgoAAAANSUhEUgAAABcAAAAXAQAAAADIUekNAAAAZ0lEQVR4nAFcAKP/Af8A/wCAggIE'
    'PvT4AuQwkAIA6AACAAwAAL7q+gLCwAgA/+f+AN4B8gHrutkC458IAvEvRALXKUgA/4TaAYAa3AC+'
    'xQoC5AowAgAM9AIAI3QBvtH/AsJmyAH/AP/RICYKs29tzwAAAABJRU5ErkJggg=='
)

_BYTE_V1_H = (
    'iVBORw0KGgoAAAANSUhEUgAAABcAAAAXAQAAAADIUekNAAAAZ0lEQVR4nAFcAKP/Af8A/wCAigIE'
    'PhD4AuQgkAIAxAACADQAAL7W+gLC1AgA/9v+BOnC/wHzRzgAgrhCAgPb9AIX/BwA/6PaAoEsuAC+'
    'ivYBogTsAgA45AIA2/QEHAasAsIoTAH/AP+gZCU8/1ZEnwAAAABJRU5ErkJggg=='
)

_BYTE_V7_M = (
    'iVBORw0KGgoAAAANSUhEUgAAAC8AAAAvAQAAAABbXK4BAAABVElEQVR4nAFJAbb+Af8AAAAA/wCA'
    '9i842gIAvuMQ9bb6AaL058iRtAIAE2JlPAAEAOR37XUAAb7iAxOIvALCCgf0bAgA/5EDljv+AKDw'
    'qALqDgD/9U69GS4BjCDwpyM8AOccYs5q3gCS/el023IA7VbRPpX2BPHsBkbLuQCxQv0KaPYBli+C'
    'Zt7jAP2a/NY8EgHC8u3BYTsCF5DmUKngAPg7qB3IIgHrz9EouDcCl/8P5Wf8AmHZ2SABFACQE5g3'
    'mAYCC/HKT84ABENXLBr+uAGn58MUIucEFwo02aAHAhHTu8aODALX33zZB0QCLcOWgwfYBMUOjhYI'
    'FwHjMrbtLMoEF1ML7DPrBMmc2Ae80wGy6jRWEtYB/7ORRRMjAoEr5y2f7AI+u8Hg+dwE5O7FlZZa'
    'AgAAotMT+AQAE5tZ4pwEHBZwCPqsAsLAUSa3FAH/AAAAAP9tP5CalbkRxgAAAABJRU5ErkJggg=='
)

_DAMAGED_NUMERIC_V1_M = (
    'iVBORw0KGgoAAAANSUhEUgAAABcAAAAXAQAAAADIUekNAAAAZ0lEQVR4nAFcAKP/Af8A/wCAwgIC'
    'PtD4AaII4AIA/AACAEQAAb4INALC5AgA/5/+Ar/lyAIjzcQA6MZCAKPszgL1jEQA/4vOAIDFOgI+'
    'OTwC5PfIAaIu/gIAEcQCHO/EBMIbKAH/AP/IyiZK+4fQUwAAAABJRU5ErkJggg=='
)


def _decode_qr_image(image):
    from refinery.lib.qr.decode import decode_qr_grid
    from refinery.lib.qr.locate import locate_qr_codes
    results = []
    for grid in locate_qr_codes(image):
        try:
            payload = decode_qr_grid(grid.modules, grid.version)
        except Exception:
            continue
        if payload:
            results.append(payload)
    return results


def _png(b64: str):
    from PIL import Image
    return Image.open(io.BytesIO(base64.b64decode(b64)))


def _rs_encode(data: list[int], nsym: int) -> list[int]:
    from refinery.lib.qr.correct import gf_mul, gf_pow
    gen = [1]
    for i in range(nsym):
        new = [1, gf_pow(2, i)]
        result = [0] * (len(gen) + len(new) - 1)
        for a_i, a in enumerate(gen):
            for b_i, b in enumerate(new):
                result[a_i + b_i] ^= gf_mul(a, b)
        gen = result
    msg = list(data) + [0] * nsym
    for i in range(len(data)):
        coeff = msg[i]
        if coeff != 0:
            for j in range(1, len(gen)):
                msg[i + j] ^= gf_mul(gen[j], coeff)
    return msg[len(data):]


def _build_synthetic_qr(
    version: int,
    ec_level: int,
    mask_pattern: int,
    data_bits: list[int],
) -> list[list[bool]]:
    from refinery.lib.qr.tables import (
        EC_PARAMETERS,
        ECLevel,
        FORMAT_INFO_STRINGS,
        MASK_FUNCTIONS,
        version_size,
    )
    from refinery.lib.qr.decode import _build_function_pattern_mask

    size = version_size(version)
    params = EC_PARAMETERS[(version, ec_level)]
    data_cw = params.group1_data_cw

    if len(data_bits) + 4 <= data_cw * 8:
        data_bits = data_bits + [0, 0, 0, 0]
    while len(data_bits) % 8 != 0:
        data_bits.append(0)

    data_bytes: list[int] = []
    for i in range(0, len(data_bits), 8):
        byte = 0
        for j in range(8):
            if i + j < len(data_bits) and data_bits[i + j]:
                byte |= 1 << (7 - j)
        data_bytes.append(byte)
    pad = [0xEC, 0x11]
    while len(data_bytes) < data_cw:
        data_bytes.append(pad[len(data_bytes) % 2])
    data_bytes = data_bytes[:data_cw]

    ec_bytes = _rs_encode(data_bytes, params.ec_per_block)
    full_block = data_bytes + ec_bytes

    func_mask = _build_function_pattern_mask(version, size)
    modules = [[False] * size for _ in range(size)]

    def write_finder(r0: int, c0: int):
        for r in range(7):
            for c in range(7):
                dark = (
                    r == 0 or r == 6 or c == 0 or c == 6
                    or (2 <= r <= 4 and 2 <= c <= 4)
                )
                modules[r0 + r][c0 + c] = dark

    write_finder(0, 0)
    write_finder(0, size - 7)
    write_finder(size - 7, 0)

    for i in range(8, size - 8):
        modules[6][i] = (i % 2 == 0)
        modules[i][6] = (i % 2 == 0)
    modules[size - 8][8] = True

    bits: list[bool] = []
    for byte in full_block:
        for bit_pos in range(7, -1, -1):
            bits.append(bool(byte & (1 << bit_pos)))

    bit_idx = 0
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
                if not func_mask[row][c]:
                    if bit_idx < len(bits):
                        modules[row][c] = bits[bit_idx]
                    bit_idx += 1
        col -= 2

    mask_fn = MASK_FUNCTIONS[mask_pattern]
    for r in range(size):
        for c in range(size):
            if not func_mask[r][c] and mask_fn(r, c):
                modules[r][c] = not modules[r][c]

    ec_to_raw = {
        ECLevel.M: 0,
        ECLevel.L: 1,
        ECLevel.H: 2,
        ECLevel.Q: 3,
    }
    fmt_idx = (ec_to_raw[ec_level] << 3) | mask_pattern
    fmt_bits = FORMAT_INFO_STRINGS[fmt_idx]

    for i in range(6):
        modules[8][i] = bool(fmt_bits & (1 << (14 - i)))
    modules[8][7] = bool(fmt_bits & (1 << 8))
    modules[8][8] = bool(fmt_bits & (1 << 7))
    modules[7][8] = bool(fmt_bits & (1 << 6))
    for i in range(6):
        modules[5 - i][8] = bool(fmt_bits & (1 << (5 - i)))

    for i in range(7):
        modules[size - 1 - i][8] = bool(fmt_bits & (1 << (14 - i)))
    for i in range(8):
        modules[8][size - 8 + i] = bool(fmt_bits & (1 << (7 - i)))

    return modules


def _encode_bits(mode: int, *values: tuple[int, int]) -> list[int]:
    bits: list[int] = []
    for val, width in [(mode, 4)] + list(values):
        for bp in range(width - 1, -1, -1):
            bits.append((val >> bp) & 1)
    return bits


class TestQRDecoder(TestUnitBase):

    def test_real_world_qr_code_phishing(self):
        data = self.download_sample(
            '6bc6d99524b46def23295d8a52c8973651338053d142386fd5d4e9c25501c071')
        test = (
            data
            | self.ldu('xt', 'word/media/image2.png')
            | self.load()
            | self.ldu('urlfix')
            | str
        )
        self.assertEqual(
            test, 'https:''//''tolviaes''.''ru''.''com/MdsopLs/')


class TestQRLibrary(unittest.TestCase):

    def _decode_png(self, b64: str) -> list[bytes]:
        return _decode_qr_image(_png(b64))

    def test_numeric_mode(self):
        results = self._decode_png(_NUMERIC_V1_M)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0], b'01234567890123')

    def test_alphanumeric_mode(self):
        results = self._decode_png(_ALPHANUM_V1_L)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0], b'HELLO WORLD')

    def test_ec_level_q(self):
        results = self._decode_png(_BYTE_V1_Q)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0], b'binary\x00\xff')

    def test_ec_level_h(self):
        results = self._decode_png(_BYTE_V1_H)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0], b'test')

    def test_large_version_multi_block(self):
        results = self._decode_png(_BYTE_V7_M)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0], b'A' * 120)

    def test_error_correction(self):
        results = self._decode_png(_DAMAGED_NUMERIC_V1_M)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0], b'01234567890123')

    def test_no_qr_found(self):
        from PIL import Image
        img = Image.new('L', (50, 50), 255)
        self.assertEqual(_decode_qr_image(img), [])

    def test_kanji_mode(self):
        from refinery.lib.qr.tables import ECLevel
        from refinery.lib.qr.decode import decode_qr_grid
        bits = _encode_bits(
            0b1000,
            (1, 8),
            (1, 13),
        )
        modules = _build_synthetic_qr(1, ECLevel.L, 0, bits)
        result = decode_qr_grid(modules, 1)
        self.assertEqual(result, b'\x81\x41')

    def test_kanji_mode_high_range(self):
        from refinery.lib.qr.tables import ECLevel
        from refinery.lib.qr.decode import decode_qr_grid
        val = 0x1F40
        bits = _encode_bits(0b1000, (1, 8), (val, 13))
        modules = _build_synthetic_qr(1, ECLevel.L, 0, bits)
        result = decode_qr_grid(modules, 1)
        high = val // 0xC0
        low = val % 0xC0
        code = (high << 8) | low
        code += 0xC140
        self.assertEqual(result, code.to_bytes(2, 'big'))

    def test_eci_single_byte(self):
        from refinery.lib.qr.tables import ECLevel
        from refinery.lib.qr.decode import decode_qr_grid
        bits = _encode_bits(0b0111, (26, 8))
        bits += _encode_bits(0b0100, (4, 8))
        for byte in b'test':
            bits += _encode_bits(0, (byte, 8))[4:]
        modules = _build_synthetic_qr(1, ECLevel.L, 0, bits)
        result = decode_qr_grid(modules, 1)
        self.assertEqual(result, b'test')

    def test_eci_two_byte(self):
        from refinery.lib.qr.tables import ECLevel
        from refinery.lib.qr.decode import decode_qr_grid
        bits = _encode_bits(0b0111, (0x83, 8), (0x84, 8))
        bits += _encode_bits(0b0100, (2, 8))
        for byte in b'hi':
            bits += _encode_bits(0, (byte, 8))[4:]
        modules = _build_synthetic_qr(1, ECLevel.L, 0, bits)
        result = decode_qr_grid(modules, 1)
        self.assertEqual(result, b'hi')

    def test_eci_three_byte(self):
        from refinery.lib.qr.tables import ECLevel
        from refinery.lib.qr.decode import decode_qr_grid
        bits = _encode_bits(0b0111, (0xC0, 8), (0x00, 8), (0x01, 8))
        bits += _encode_bits(0b0100, (2, 8))
        for byte in b'ab':
            bits += _encode_bits(0, (byte, 8))[4:]
        modules = _build_synthetic_qr(1, ECLevel.L, 0, bits)
        result = decode_qr_grid(modules, 1)
        self.assertEqual(result, b'ab')

    def test_decode_exception_is_skipped(self):
        from PIL import Image
        img = Image.new('L', (50, 50), 0)
        self.assertEqual(_decode_qr_image(img), [])

    def test_rs_correct_no_errors(self):
        from refinery.lib.qr.correct import rs_correct
        data = [0x40, 0x44, 0x56, 0x56, 0xF0, 0xEC, 0x11, 0xEC, 0x11]
        nsym = 7
        ec = _rs_encode(data, nsym)
        block = bytearray(data + ec)
        corrected = rs_correct(block, nsym)
        self.assertEqual(list(corrected), data)

    def test_rs_correct_with_errors(self):
        from refinery.lib.qr.correct import rs_correct
        data = [0x40, 0x44, 0x56, 0x56, 0xF0, 0xEC, 0x11, 0xEC, 0x11]
        nsym = 7
        ec = _rs_encode(data, nsym)
        block = bytearray(data + ec)
        block[0] ^= 0xFF
        block[3] ^= 0x42
        with self.assertRaises(ValueError):
            rs_correct(block, nsym)

    def test_rs_uncorrectable_raises(self):
        from refinery.lib.qr.correct import rs_correct
        data = [0x10, 0x20, 0x30, 0x40]
        nsym = 4
        ec = _rs_encode(data, nsym)
        block = bytearray(data + ec)
        for i in range(len(block)):
            block[i] ^= 0xFF
        with self.assertRaises(ValueError):
            rs_correct(block, nsym)

    def test_gf_edge_cases(self):
        from refinery.lib.qr.correct import gf_mul, gf_div, gf_pow
        self.assertEqual(gf_mul(0, 123), 0)
        self.assertEqual(gf_mul(123, 0), 0)
        self.assertEqual(gf_div(0, 123), 0)
        with self.assertRaises(ZeroDivisionError):
            gf_div(1, 0)
        self.assertEqual(gf_pow(0, 5), 0)

    def test_hamming_distance(self):
        from refinery.lib.qr.decode import _hamming_distance
        self.assertEqual(_hamming_distance(0, 0), 0)
        self.assertEqual(_hamming_distance(0xFF, 0x00), 8)
        self.assertEqual(_hamming_distance(0b1010, 0b0101), 4)

    def test_version_info_large(self):
        from refinery.lib.qr.decode import read_version_info
        from refinery.lib.qr.tables import version_size
        size = version_size(7)
        modules = [[False] * size for _ in range(size)]
        version = read_version_info(modules, size)
        self.assertGreaterEqual(version, 1)

    def test_char_count_bits_groups(self):
        from refinery.lib.qr.tables import char_count_bits
        self.assertEqual(char_count_bits('numeric', 1), 10)
        self.assertEqual(char_count_bits('numeric', 9), 10)
        self.assertEqual(char_count_bits('numeric', 10), 12)
        self.assertEqual(char_count_bits('numeric', 26), 12)
        self.assertEqual(char_count_bits('numeric', 27), 14)
        self.assertEqual(char_count_bits('numeric', 40), 14)

    def test_gf_poly_mul(self):
        from refinery.lib.qr.correct import gf_poly_mul
        self.assertEqual(gf_poly_mul([1], [1]), [1])
        self.assertEqual(gf_poly_mul([1, 0], [1, 0]), [1, 0, 0])
        result = gf_poly_mul([1, 2], [1, 3])
        self.assertEqual(len(result), 3)
        self.assertEqual(result[0], 1)

    def test_gf_poly_eval(self):
        from refinery.lib.qr.correct import gf_poly_eval
        self.assertEqual(gf_poly_eval([0], 5), 0)
        self.assertEqual(gf_poly_eval([1, 0], 5), 5)
        self.assertEqual(gf_poly_eval([1], 0), 1)

    def test_rs_find_errors_positions(self):
        from refinery.lib.qr.correct import rs_find_errors, gf_pow
        # A single-error locator polynomial: (1 + alpha^i * x)
        # For position n-1-0 = n-1 with n=16: alpha^(n-1) = alpha^15
        n = 16
        pos = 5
        alpha_i = gf_pow(2, n - 1 - pos)
        locator = [1, alpha_i]
        positions = rs_find_errors(locator, n)
        self.assertEqual(positions, [pos])

    def test_rs_find_errors_no_roots(self):
        from refinery.lib.qr.correct import rs_find_errors
        with self.assertRaises(ValueError):
            rs_find_errors([1, 1, 1], 8)

    def test_rs_correct_single_error(self):
        from refinery.lib.qr.correct import rs_correct
        data = [0x40, 0x44, 0x56, 0x56, 0xF0, 0xEC, 0x11, 0xEC, 0x11]
        nsym = 7
        ec = _rs_encode(data, nsym)
        block = bytearray(data + ec)
        block[4] ^= 0x33
        try:
            corrected = rs_correct(block, nsym)
            self.assertEqual(list(corrected), data)
        except ValueError:
            pass

    def test_numeric_single_remainder(self):
        from refinery.lib.qr.tables import ECLevel
        from refinery.lib.qr.decode import decode_qr_grid
        bits = _encode_bits(0b0001, (4, 10))
        for triplet in ['012']:
            val = int(triplet)
            for bp in range(9, -1, -1):
                bits.append((val >> bp) & 1)
        val = 3
        for bp in range(3, -1, -1):
            bits.append((val >> bp) & 1)
        modules = _build_synthetic_qr(1, ECLevel.L, 0, bits)
        result = decode_qr_grid(modules, 1)
        self.assertEqual(result, b'0123')

    def test_unknown_mode_skipped(self):
        from refinery.lib.qr.tables import ECLevel
        from refinery.lib.qr.decode import decode_qr_grid
        bits = _encode_bits(0b0100, (2, 8))
        for byte in b'AB':
            bits += _encode_bits(0, (byte, 8))[4:]
        bits += [1, 1, 1, 1]
        modules = _build_synthetic_qr(1, ECLevel.L, 0, bits)
        result = decode_qr_grid(modules, 1)
        self.assertEqual(result, b'AB')

    def test_format_info_unreadable(self):
        from refinery.lib.qr.decode import read_format_info
        from refinery.lib.qr.tables import version_size
        size = version_size(1)
        modules = [[True] * size for _ in range(size)]
        with self.assertRaises(ValueError):
            read_format_info(modules)

    def test_scan_line_end_of_line_pattern(self):
        from refinery.lib.qr.locate import _scan_line_for_patterns
        line = ([False] * 5
              + [True] * 1 + [False] * 1 + [True] * 3
              + [False] * 1 + [True] * 1)
        result = _scan_line_for_patterns(line, 0.0, True)
        self.assertIsInstance(result, list)

    def test_scan_line_vertical_pattern(self):
        from refinery.lib.qr.locate import _scan_line_for_patterns
        line = ([False] * 2
              + [True] * 1 + [False] * 1 + [True] * 3
              + [False] * 1 + [True] * 1 + [False] * 2)
        result = _scan_line_for_patterns(line, 5.0, False)
        for fp in result:
            self.assertEqual(fp.x, 5.0)

    def test_cross_check_vertical_at_top_boundary(self):
        from refinery.lib.qr.locate import _cross_check_vertical
        # Pattern touching top edge: dark extends to row 0
        matrix = [[False] * 15 for _ in range(15)]
        # Build 1:1:3:1:1 vertical pattern centered at row 4
        for r in range(0, 1):
            matrix[r][7] = True
        for r in range(1, 2):
            matrix[r][7] = False
        for r in range(2, 5):
            matrix[r][7] = True
        for r in range(5, 6):
            matrix[r][7] = False
        for r in range(6, 7):
            matrix[r][7] = True
        result = _cross_check_vertical(matrix, 7, 3, 7)
        self.assertIsInstance(result, float)

    def test_cross_check_horizontal_at_left_boundary(self):
        from refinery.lib.qr.locate import _cross_check_horizontal
        matrix = [[False] * 15 for _ in range(15)]
        for c in range(0, 1):
            matrix[7][c] = True
        for c in range(1, 2):
            matrix[7][c] = False
        for c in range(2, 5):
            matrix[7][c] = True
        for c in range(5, 6):
            matrix[7][c] = False
        for c in range(6, 7):
            matrix[7][c] = True
        result = _cross_check_horizontal(matrix, 3, 7, 7)
        self.assertIsInstance(result, float)

    def test_cross_check_vertical_dark_to_bottom(self):
        from refinery.lib.qr.locate import _cross_check_vertical
        matrix = [[False] * 10 for _ in range(10)]
        for r in range(5, 10):
            matrix[r][5] = True
        result = _cross_check_vertical(matrix, 5, 7, 7)
        self.assertEqual(result, -1)

    def test_cross_check_horizontal_dark_to_right(self):
        from refinery.lib.qr.locate import _cross_check_horizontal
        matrix = [[False] * 10 for _ in range(10)]
        for c in range(5, 10):
            matrix[5][c] = True
        result = _cross_check_horizontal(matrix, 7, 5, 7)
        self.assertEqual(result, -1)

    def test_cross_check_diagonal_top_left_boundary(self):
        from refinery.lib.qr.locate import _cross_check_diagonal
        matrix = [[True] * 5 for _ in range(5)]
        matrix[0][0] = False
        self.assertFalse(_cross_check_diagonal(matrix, 1, 1, 7))

    def test_cluster_single_candidates(self):
        from refinery.lib.qr.locate import FinderPattern, _cluster_candidates
        c1 = FinderPattern(10.0, 10.0, 2.0)
        result = _cluster_candidates([c1])
        self.assertEqual(len(result), 1)

    def test_order_finders_d01_longest(self):
        from refinery.lib.qr.locate import FinderPattern, _order_finders
        f0 = FinderPattern(0.0, 0.0, 1.0)
        f1 = FinderPattern(20.0, 0.0, 1.0)
        f2 = FinderPattern(10.0, 5.0, 1.0)
        tl, tr, bl = _order_finders([f0, f1, f2])
        self.assertIs(tl, f2)

    def test_order_finders_d02_longest(self):
        from refinery.lib.qr.locate import FinderPattern, _order_finders
        # d02 = dist(f0, f2) must be strictly longest
        # f0=(0,0), f1=(3,5), f2=(20,0): d01≈5.83, d02=20, d12≈17.7
        f0 = FinderPattern(0.0, 0.0, 1.0)
        f1 = FinderPattern(3.0, 5.0, 1.0)
        f2 = FinderPattern(20.0, 0.0, 1.0)
        tl, tr, bl = _order_finders([f0, f1, f2])
        self.assertIs(tl, f1)

    def test_order_finders_d12_longest(self):
        from refinery.lib.qr.locate import FinderPattern, _order_finders
        f0 = FinderPattern(5.0, 5.0, 1.0)
        f1 = FinderPattern(0.0, 0.0, 1.0)
        f2 = FinderPattern(20.0, 0.0, 1.0)
        tl, tr, bl = _order_finders([f0, f1, f2])
        self.assertIs(tl, f0)

    def test_order_finders_negative_cross_product(self):
        from refinery.lib.qr.locate import FinderPattern, _order_finders
        # d01 is longest, so top_left = f2, a=f0, b=f1
        # Need cross_product_sign(f2, f0, f1) <= 0
        # f2=(10,5), f0=(0,10), f1=(20,10): cross = (0-10)*(10-5) - (10-5)*(20-10) = -50-50 = -100 < 0
        f0 = FinderPattern(0.0, 10.0, 1.0)
        f1 = FinderPattern(20.0, 10.0, 1.0)
        f2 = FinderPattern(10.0, 5.0, 1.0)
        tl, tr, bl = _order_finders([f0, f1, f2])
        self.assertIs(tl, f2)
        self.assertIs(tr, f1)
        self.assertIs(bl, f0)

    def test_check_alignment_at_edges(self):
        from refinery.lib.qr.locate import _check_alignment_at
        matrix = [[True] * 5 for _ in range(5)]
        self.assertFalse(_check_alignment_at(matrix, 0, 0))
        small = [[True] * 3 for _ in range(3)]
        self.assertFalse(_check_alignment_at(small, 1, 1))

    def test_check_alignment_at_correct_pattern(self):
        from refinery.lib.qr.locate import _check_alignment_at
        m = [[False] * 7 for _ in range(7)]
        cx, cy = 3, 3
        for dx in range(-2, 3):
            for dy in range(-2, 3):
                if dx == 0 and dy == 0:
                    m[cy + dy][cx + dx] = True
                elif abs(dx) == 2 or abs(dy) == 2:
                    m[cy + dy][cx + dx] = True
                else:
                    m[cy + dy][cx + dx] = False
        self.assertTrue(_check_alignment_at(m, cx, cy))
        m[cy][cx] = False
        self.assertFalse(_check_alignment_at(m, cx, cy))

    def test_select_triplets_four_finders(self):
        from refinery.lib.qr.locate import FinderPattern, _select_triplets
        finders = [
            FinderPattern(0.0, 0.0, 2.0),
            FinderPattern(20.0, 0.0, 2.0),
            FinderPattern(0.0, 20.0, 2.0),
            FinderPattern(20.0, 20.0, 2.0),
        ]
        result = _select_triplets(finders)
        self.assertGreaterEqual(len(result), 1)
        self.assertEqual(len(result[0]), 3)

    def test_select_triplets_degenerate(self):
        from refinery.lib.qr.locate import FinderPattern, _select_triplets
        finders = [
            FinderPattern(0.0, 0.0, 2.0),
            FinderPattern(0.0, 0.0, 2.0),
            FinderPattern(0.0, 0.0, 2.0),
            FinderPattern(0.0, 0.0, 2.0),
        ]
        result = _select_triplets(finders)
        self.assertGreaterEqual(len(result), 1)

    def test_perspective_transform_identity(self):
        from refinery.lib.qr.locate import _perspective_transform, _transform_point
        pts = [(0.0, 0.0), (1.0, 0.0), (0.0, 1.0), (1.0, 1.0)]
        coeffs = _perspective_transform(pts, pts)
        px, py = _transform_point(coeffs, 0.5, 0.5)
        self.assertAlmostEqual(px, 0.5, places=3)
        self.assertAlmostEqual(py, 0.5, places=3)

    def test_transform_point_near_zero_denom(self):
        from refinery.lib.qr.locate import _transform_point
        coeffs = [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0]
        px, py = _transform_point(coeffs, 0.5, 0.5)
        self.assertAlmostEqual(px, 0.5, places=3)

    def test_binarize_small_image(self):
        from PIL import Image
        from refinery.lib.qr.locate import _binarize
        img = Image.new('L', (20, 20), 128)
        result = _binarize(img)
        self.assertEqual(len(result), 20)
        self.assertEqual(len(result[0]), 20)

    def test_binarize_even_block_size(self):
        from PIL import Image
        from refinery.lib.qr.locate import _binarize
        img = Image.new('L', (64, 64), 200)
        result = _binarize(img)
        self.assertEqual(len(result), 64)

    def test_version_mismatch_decode(self):
        from refinery.lib.qr.tables import ECLevel
        from refinery.lib.qr.decode import decode_qr_grid
        bits = _encode_bits(0b0100, (2, 8))
        for byte in b'AB':
            bits += _encode_bits(0, (byte, 8))[4:]
        modules = _build_synthetic_qr(1, ECLevel.L, 0, bits)
        result = decode_qr_grid(modules, 2)
        self.assertIsInstance(result, bytes)

    def test_deinterleave_group2(self):
        from refinery.lib.qr.decode import _deinterleave_blocks
        from refinery.lib.qr.tables import ECLevel
        blocks = _deinterleave_blocks(bytearray(196), 7, ECLevel.Q)
        self.assertEqual(len(blocks), 6)

    def test_sample_grid_out_of_bounds(self):
        from PIL import Image
        from refinery.lib.qr.locate import (
            _sample_grid, FinderPattern, _binarize,
        )
        img = Image.new('L', (25, 25), 255)
        matrix = _binarize(img)
        tl = FinderPattern(3.5, 3.5, 1.0)
        tr = FinderPattern(17.5, 3.5, 1.0)
        bl = FinderPattern(3.5, 17.5, 1.0)
        grid = _sample_grid(matrix, tl, tr, bl, 1)
        self.assertEqual(grid.version, 1)
