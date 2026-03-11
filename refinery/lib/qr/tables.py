from __future__ import annotations

import enum

from typing import Callable, NamedTuple


class ECLevel(enum.IntEnum):
    L = 0
    M = 1
    Q = 2
    H = 3


class ECBlockInfo(NamedTuple):
    total_codewords: int
    ec_per_block: int
    group1_blocks: int
    group1_data_cw: int
    group2_blocks: int
    group2_data_cw: int


def version_size(version: int) -> int:
    return 4 * version + 17


ALIGNMENT_POSITIONS: dict[int, list[int]] = {
    1: [],
    2: [6, 18],
    3: [6, 22],
    4: [6, 26],
    5: [6, 30],
    6: [6, 34],
    7: [6, 22, 38],
    8: [6, 24, 42],
    9: [6, 26, 46],
    10: [6, 28, 50],
    11: [6, 30, 54],
    12: [6, 32, 58],
    13: [6, 34, 62],
    14: [6, 26, 46, 66],
    15: [6, 26, 48, 70],
    16: [6, 26, 50, 74],
    17: [6, 30, 54, 78],
    18: [6, 30, 56, 82],
    19: [6, 30, 58, 86],
    20: [6, 34, 62, 90],
    21: [6, 28, 50, 72, 94],
    22: [6, 26, 50, 74, 98],
    23: [6, 30, 54, 78, 102],
    24: [6, 28, 54, 80, 106],
    25: [6, 32, 58, 84, 110],
    26: [6, 30, 58, 86, 114],
    27: [6, 34, 62, 90, 118],
    28: [6, 26, 50, 74, 98, 122],
    29: [6, 30, 54, 78, 102, 126],
    30: [6, 26, 52, 78, 104, 130],
    31: [6, 30, 56, 82, 108, 134],
    32: [6, 34, 60, 86, 112, 138],
    33: [6, 30, 58, 86, 114, 142],
    34: [6, 34, 62, 90, 118, 146],
    35: [6, 30, 54, 78, 102, 126, 150],
    36: [6, 24, 50, 76, 102, 128, 154],
    37: [6, 28, 54, 80, 106, 132, 158],
    38: [6, 32, 58, 84, 110, 136, 162],
    39: [6, 26, 54, 82, 110, 138, 166],
    40: [6, 30, 58, 86, 114, 142, 170],
}

EC_PARAMETERS: dict[tuple[int, ECLevel], ECBlockInfo] = {
    ( 1, ECLevel.L): ECBlockInfo(  26,  7,  1,  19,  0,   0), # noqa
    ( 1, ECLevel.M): ECBlockInfo(  26, 10,  1,  16,  0,   0), # noqa
    ( 1, ECLevel.Q): ECBlockInfo(  26, 13,  1,  13,  0,   0), # noqa
    ( 1, ECLevel.H): ECBlockInfo(  26, 17,  1,   9,  0,   0), # noqa
    ( 2, ECLevel.L): ECBlockInfo(  44, 10,  1,  34,  0,   0), # noqa
    ( 2, ECLevel.M): ECBlockInfo(  44, 16,  1,  28,  0,   0), # noqa
    ( 2, ECLevel.Q): ECBlockInfo(  44, 22,  1,  22,  0,   0), # noqa
    ( 2, ECLevel.H): ECBlockInfo(  44, 28,  1,  16,  0,   0), # noqa
    ( 3, ECLevel.L): ECBlockInfo(  70, 15,  1,  55,  0,   0), # noqa
    ( 3, ECLevel.M): ECBlockInfo(  70, 26,  1,  44,  0,   0), # noqa
    ( 3, ECLevel.Q): ECBlockInfo(  70, 18,  2,  17,  0,   0), # noqa
    ( 3, ECLevel.H): ECBlockInfo(  70, 22,  2,  13,  0,   0), # noqa
    ( 4, ECLevel.L): ECBlockInfo( 100, 20,  1,  80,  0,   0), # noqa
    ( 4, ECLevel.M): ECBlockInfo( 100, 18,  2,  32,  0,   0), # noqa
    ( 4, ECLevel.Q): ECBlockInfo( 100, 26,  2,  24,  0,   0), # noqa
    ( 4, ECLevel.H): ECBlockInfo( 100, 16,  4,   9,  0,   0), # noqa
    ( 5, ECLevel.L): ECBlockInfo( 134, 26,  1, 108,  0,   0), # noqa
    ( 5, ECLevel.M): ECBlockInfo( 134, 24,  2,  43,  0,   0), # noqa
    ( 5, ECLevel.Q): ECBlockInfo( 134, 18,  2,  15,  2,  16), # noqa
    ( 5, ECLevel.H): ECBlockInfo( 134, 22,  2,  11,  2,  12), # noqa
    ( 6, ECLevel.L): ECBlockInfo( 172, 18,  2,  68,  0,   0), # noqa
    ( 6, ECLevel.M): ECBlockInfo( 172, 16,  4,  27,  0,   0), # noqa
    ( 6, ECLevel.Q): ECBlockInfo( 172, 24,  4,  19,  0,   0), # noqa
    ( 6, ECLevel.H): ECBlockInfo( 172, 28,  4,  15,  0,   0), # noqa
    ( 7, ECLevel.L): ECBlockInfo( 196, 20,  2,  78,  0,   0), # noqa
    ( 7, ECLevel.M): ECBlockInfo( 196, 18,  4,  31,  0,   0), # noqa
    ( 7, ECLevel.Q): ECBlockInfo( 196, 18,  2,  14,  4,  15), # noqa
    ( 7, ECLevel.H): ECBlockInfo( 196, 26,  4,  13,  1,  14), # noqa
    ( 8, ECLevel.L): ECBlockInfo( 242, 24,  2,  97,  0,   0), # noqa
    ( 8, ECLevel.M): ECBlockInfo( 242, 22,  2,  38,  2,  39), # noqa
    ( 8, ECLevel.Q): ECBlockInfo( 242, 22,  4,  18,  2,  19), # noqa
    ( 8, ECLevel.H): ECBlockInfo( 242, 26,  4,  14,  2,  15), # noqa
    ( 9, ECLevel.L): ECBlockInfo( 292, 30,  2, 116,  0,   0), # noqa
    ( 9, ECLevel.M): ECBlockInfo( 292, 22,  3,  36,  2,  37), # noqa
    ( 9, ECLevel.Q): ECBlockInfo( 292, 20,  4,  16,  4,  17), # noqa
    ( 9, ECLevel.H): ECBlockInfo( 292, 24,  4,  12,  4,  13), # noqa
    (10, ECLevel.L): ECBlockInfo( 346, 18,  2,  68,  2,  69), # noqa
    (10, ECLevel.M): ECBlockInfo( 346, 26,  4,  43,  1,  44), # noqa
    (10, ECLevel.Q): ECBlockInfo( 346, 24,  6,  19,  2,  20), # noqa
    (10, ECLevel.H): ECBlockInfo( 346, 28,  6,  15,  2,  16), # noqa
    (11, ECLevel.L): ECBlockInfo( 404, 20,  4,  81,  0,   0), # noqa
    (11, ECLevel.M): ECBlockInfo( 404, 30,  1,  50,  4,  51), # noqa
    (11, ECLevel.Q): ECBlockInfo( 404, 28,  4,  22,  4,  23), # noqa
    (11, ECLevel.H): ECBlockInfo( 404, 24,  3,  12,  8,  13), # noqa
    (12, ECLevel.L): ECBlockInfo( 466, 24,  2,  92,  2,  93), # noqa
    (12, ECLevel.M): ECBlockInfo( 466, 22,  6,  36,  2,  37), # noqa
    (12, ECLevel.Q): ECBlockInfo( 466, 26,  4,  20,  6,  21), # noqa
    (12, ECLevel.H): ECBlockInfo( 466, 28,  7,  14,  4,  15), # noqa
    (13, ECLevel.L): ECBlockInfo( 532, 26,  4, 107,  0,   0), # noqa
    (13, ECLevel.M): ECBlockInfo( 532, 22,  8,  37,  1,  38), # noqa
    (13, ECLevel.Q): ECBlockInfo( 532, 24,  8,  20,  4,  21), # noqa
    (13, ECLevel.H): ECBlockInfo( 532, 22, 12,  11,  4,  12), # noqa
    (14, ECLevel.L): ECBlockInfo( 581, 30,  3, 115,  1, 116), # noqa
    (14, ECLevel.M): ECBlockInfo( 581, 24,  4,  40,  5,  41), # noqa
    (14, ECLevel.Q): ECBlockInfo( 581, 20, 11,  16,  5,  17), # noqa
    (14, ECLevel.H): ECBlockInfo( 581, 24, 11,  12,  5,  13), # noqa
    (15, ECLevel.L): ECBlockInfo( 655, 22,  5,  87,  1,  88), # noqa
    (15, ECLevel.M): ECBlockInfo( 655, 24,  5,  41,  5,  42), # noqa
    (15, ECLevel.Q): ECBlockInfo( 655, 30,  5,  24,  7,  25), # noqa
    (15, ECLevel.H): ECBlockInfo( 655, 24, 11,  12,  7,  13), # noqa
    (16, ECLevel.L): ECBlockInfo( 733, 24,  5,  98,  1,  99), # noqa
    (16, ECLevel.M): ECBlockInfo( 733, 28,  7,  45,  3,  46), # noqa
    (16, ECLevel.Q): ECBlockInfo( 733, 24, 15,  19,  2,  20), # noqa
    (16, ECLevel.H): ECBlockInfo( 733, 30,  3,  15, 13,  16), # noqa
    (17, ECLevel.L): ECBlockInfo( 815, 28,  1, 107,  5, 108), # noqa
    (17, ECLevel.M): ECBlockInfo( 815, 28, 10,  46,  1,  47), # noqa
    (17, ECLevel.Q): ECBlockInfo( 815, 28,  1,  22, 15,  23), # noqa
    (17, ECLevel.H): ECBlockInfo( 815, 28,  2,  14, 17,  15), # noqa
    (18, ECLevel.L): ECBlockInfo( 901, 30,  5, 120,  1, 121), # noqa
    (18, ECLevel.M): ECBlockInfo( 901, 26,  9,  43,  4,  44), # noqa
    (18, ECLevel.Q): ECBlockInfo( 901, 28, 17,  22,  1,  23), # noqa
    (18, ECLevel.H): ECBlockInfo( 901, 28,  2,  14, 19,  15), # noqa
    (19, ECLevel.L): ECBlockInfo( 991, 28,  3, 113,  4, 114), # noqa
    (19, ECLevel.M): ECBlockInfo( 991, 26,  3,  44, 11,  45), # noqa
    (19, ECLevel.Q): ECBlockInfo( 991, 26, 17,  21,  4,  22), # noqa
    (19, ECLevel.H): ECBlockInfo( 991, 26,  9,  13, 16,  14), # noqa
    (20, ECLevel.L): ECBlockInfo(1085, 28,  3, 107,  5, 108), # noqa
    (20, ECLevel.M): ECBlockInfo(1085, 26,  3,  41, 13,  42), # noqa
    (20, ECLevel.Q): ECBlockInfo(1085, 30, 15,  24,  5,  25), # noqa
    (20, ECLevel.H): ECBlockInfo(1085, 28, 15,  15, 10,  16), # noqa
    (21, ECLevel.L): ECBlockInfo(1156, 28,  4, 116,  4, 117), # noqa
    (21, ECLevel.M): ECBlockInfo(1156, 26, 17,  42,  0,   0), # noqa
    (21, ECLevel.Q): ECBlockInfo(1156, 28, 17,  22,  6,  23), # noqa
    (21, ECLevel.H): ECBlockInfo(1156, 30, 19,  16,  6,  17), # noqa
    (22, ECLevel.L): ECBlockInfo(1258, 28,  2, 111,  7, 112), # noqa
    (22, ECLevel.M): ECBlockInfo(1258, 28, 17,  46,  0,   0), # noqa
    (22, ECLevel.Q): ECBlockInfo(1258, 30,  7,  24, 16,  25), # noqa
    (22, ECLevel.H): ECBlockInfo(1258, 24, 34,  13,  0,   0), # noqa
    (23, ECLevel.L): ECBlockInfo(1364, 30,  4, 121,  5, 122), # noqa
    (23, ECLevel.M): ECBlockInfo(1364, 28,  4,  47, 14,  48), # noqa
    (23, ECLevel.Q): ECBlockInfo(1364, 30, 11,  24, 14,  25), # noqa
    (23, ECLevel.H): ECBlockInfo(1364, 30, 16,  15, 14,  16), # noqa
    (24, ECLevel.L): ECBlockInfo(1474, 30,  6, 117,  4, 118), # noqa
    (24, ECLevel.M): ECBlockInfo(1474, 28,  6,  45, 14,  46), # noqa
    (24, ECLevel.Q): ECBlockInfo(1474, 30, 11,  24, 16,  25), # noqa
    (24, ECLevel.H): ECBlockInfo(1474, 30, 30,  16,  2,  17), # noqa
    (25, ECLevel.L): ECBlockInfo(1588, 26,  8, 106,  4, 107), # noqa
    (25, ECLevel.M): ECBlockInfo(1588, 28,  8,  47, 13,  48), # noqa
    (25, ECLevel.Q): ECBlockInfo(1588, 30,  7,  24, 22,  25), # noqa
    (25, ECLevel.H): ECBlockInfo(1588, 30, 22,  15, 13,  16), # noqa
    (26, ECLevel.L): ECBlockInfo(1706, 28, 10, 114,  2, 115), # noqa
    (26, ECLevel.M): ECBlockInfo(1706, 28, 19,  46,  4,  47), # noqa
    (26, ECLevel.Q): ECBlockInfo(1706, 28, 28,  22,  6,  23), # noqa
    (26, ECLevel.H): ECBlockInfo(1706, 30, 33,  16,  4,  17), # noqa
    (27, ECLevel.L): ECBlockInfo(1828, 30,  8, 122,  4, 123), # noqa
    (27, ECLevel.M): ECBlockInfo(1828, 28, 22,  45,  3,  46), # noqa
    (27, ECLevel.Q): ECBlockInfo(1828, 30,  8,  23, 26,  24), # noqa
    (27, ECLevel.H): ECBlockInfo(1828, 30, 12,  15, 28,  16), # noqa
    (28, ECLevel.L): ECBlockInfo(1921, 30,  3, 117, 10, 118), # noqa
    (28, ECLevel.M): ECBlockInfo(1921, 28,  3,  45, 23,  46), # noqa
    (28, ECLevel.Q): ECBlockInfo(1921, 30,  4,  24, 31,  25), # noqa
    (28, ECLevel.H): ECBlockInfo(1921, 30, 11,  15, 31,  16), # noqa
    (29, ECLevel.L): ECBlockInfo(2051, 30,  7, 116,  7, 117), # noqa
    (29, ECLevel.M): ECBlockInfo(2051, 28, 21,  45,  7,  46), # noqa
    (29, ECLevel.Q): ECBlockInfo(2051, 30,  1,  23, 37,  24), # noqa
    (29, ECLevel.H): ECBlockInfo(2051, 30, 19,  15, 26,  16), # noqa
    (30, ECLevel.L): ECBlockInfo(2185, 30,  5, 115, 10, 116), # noqa
    (30, ECLevel.M): ECBlockInfo(2185, 28, 19,  47, 10,  48), # noqa
    (30, ECLevel.Q): ECBlockInfo(2185, 30, 15,  24, 25,  25), # noqa
    (30, ECLevel.H): ECBlockInfo(2185, 30, 23,  15, 25,  16), # noqa
    (31, ECLevel.L): ECBlockInfo(2323, 30, 13, 115,  3, 116), # noqa
    (31, ECLevel.M): ECBlockInfo(2323, 28,  2,  46, 29,  47), # noqa
    (31, ECLevel.Q): ECBlockInfo(2323, 30, 42,  24,  1,  25), # noqa
    (31, ECLevel.H): ECBlockInfo(2323, 30, 23,  15, 28,  16), # noqa
    (32, ECLevel.L): ECBlockInfo(2465, 30, 17, 115,  0,   0), # noqa
    (32, ECLevel.M): ECBlockInfo(2465, 28, 10,  46, 23,  47), # noqa
    (32, ECLevel.Q): ECBlockInfo(2465, 30, 10,  24, 35,  25), # noqa
    (32, ECLevel.H): ECBlockInfo(2465, 30, 19,  15, 35,  16), # noqa
    (33, ECLevel.L): ECBlockInfo(2611, 30, 17, 115,  1, 116), # noqa
    (33, ECLevel.M): ECBlockInfo(2611, 28, 14,  46, 21,  47), # noqa
    (33, ECLevel.Q): ECBlockInfo(2611, 30, 29,  24, 19,  25), # noqa
    (33, ECLevel.H): ECBlockInfo(2611, 30, 11,  15, 46,  16), # noqa
    (34, ECLevel.L): ECBlockInfo(2761, 30, 13, 115,  6, 116), # noqa
    (34, ECLevel.M): ECBlockInfo(2761, 28, 14,  46, 23,  47), # noqa
    (34, ECLevel.Q): ECBlockInfo(2761, 30, 44,  24,  7,  25), # noqa
    (34, ECLevel.H): ECBlockInfo(2761, 30, 59,  16,  1,  17), # noqa
    (35, ECLevel.L): ECBlockInfo(2876, 30, 12, 121,  7, 122), # noqa
    (35, ECLevel.M): ECBlockInfo(2876, 28, 12,  47, 26,  48), # noqa
    (35, ECLevel.Q): ECBlockInfo(2876, 30, 39,  24, 14,  25), # noqa
    (35, ECLevel.H): ECBlockInfo(2876, 30, 22,  15, 41,  16), # noqa
    (36, ECLevel.L): ECBlockInfo(3034, 30,  6, 121, 14, 122), # noqa
    (36, ECLevel.M): ECBlockInfo(3034, 28,  6,  47, 34,  48), # noqa
    (36, ECLevel.Q): ECBlockInfo(3034, 30, 46,  24, 10,  25), # noqa
    (36, ECLevel.H): ECBlockInfo(3034, 30,  2,  15, 64,  16), # noqa
    (37, ECLevel.L): ECBlockInfo(3196, 30, 17, 122,  4, 123), # noqa
    (37, ECLevel.M): ECBlockInfo(3196, 28, 29,  46, 14,  47), # noqa
    (37, ECLevel.Q): ECBlockInfo(3196, 30, 49,  24, 10,  25), # noqa
    (37, ECLevel.H): ECBlockInfo(3196, 30, 24,  15, 46,  16), # noqa
    (38, ECLevel.L): ECBlockInfo(3362, 30,  4, 122, 18, 123), # noqa
    (38, ECLevel.M): ECBlockInfo(3362, 28, 13,  46, 32,  47), # noqa
    (38, ECLevel.Q): ECBlockInfo(3362, 30, 48,  24, 14,  25), # noqa
    (38, ECLevel.H): ECBlockInfo(3362, 30, 42,  15, 32,  16), # noqa
    (39, ECLevel.L): ECBlockInfo(3532, 30, 20, 117,  4, 118), # noqa
    (39, ECLevel.M): ECBlockInfo(3532, 28, 40,  47,  7,  48), # noqa
    (39, ECLevel.Q): ECBlockInfo(3532, 30, 43,  24, 22,  25), # noqa
    (39, ECLevel.H): ECBlockInfo(3532, 30, 10,  15, 67,  16), # noqa
    (40, ECLevel.L): ECBlockInfo(3706, 30, 19, 118,  6, 119), # noqa
    (40, ECLevel.M): ECBlockInfo(3706, 28, 18,  47, 31,  48), # noqa
    (40, ECLevel.Q): ECBlockInfo(3706, 30, 34,  24, 34,  25), # noqa
    (40, ECLevel.H): ECBlockInfo(3706, 30, 20,  15, 61,  16), # noqa
}

FORMAT_INFO_STRINGS: list[int] = [
    0x5412, 0x5125, 0x5E7C, 0x5B4B, 0x45F9, 0x40CE, 0x4F97, 0x4AA0,
    0x77C4, 0x72F3, 0x7DAA, 0x789D, 0x662F, 0x6318, 0x6C41, 0x6976,
    0x1689, 0x13BE, 0x1CE7, 0x19D0, 0x0762, 0x0255, 0x0D0C, 0x083B,
    0x355F, 0x3068, 0x3F31, 0x3A06, 0x24B4, 0x2183, 0x2EDA, 0x2BED,
]

VERSION_INFO_STRINGS: dict[int, int] = {
    7: 0x07C94,
    8: 0x085BC,
    9: 0x09A99,
    10: 0x0A4D3,
    11: 0x0BBF6,
    12: 0x0C762,
    13: 0x0D847,
    14: 0x0E60D,
    15: 0x0F928,
    16: 0x10B78,
    17: 0x1145D,
    18: 0x12A17,
    19: 0x13532,
    20: 0x149A6,
    21: 0x15683,
    22: 0x168C9,
    23: 0x177EC,
    24: 0x18EC4,
    25: 0x191E1,
    26: 0x1AFAB,
    27: 0x1B08E,
    28: 0x1CC1A,
    29: 0x1D33F,
    30: 0x1ED75,
    31: 0x1F250,
    32: 0x209D5,
    33: 0x216F0,
    34: 0x228BA,
    35: 0x2379F,
    36: 0x24B0B,
    37: 0x2542E,
    38: 0x26A64,
    39: 0x27541,
    40: 0x28C69,
}

MASK_FUNCTIONS: list[Callable[[int, int], bool]] = [
    lambda r, c: (r + c) % 2 == 0,
    lambda r, c: r % 2 == 0,
    lambda r, c: c % 3 == 0,
    lambda r, c: (r + c) % 3 == 0,
    lambda r, c: (r // 2 + c // 3) % 2 == 0,
    lambda r, c: (r * c) % 2 + (r * c) % 3 == 0,
    lambda r, c: ((r * c) % 2 + (r * c) % 3) % 2 == 0,
    lambda r, c: ((r + c) % 2 + (r * c) % 3) % 2 == 0,
]

ALPHANUMERIC_CHARSET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:'

CHAR_COUNT_BITS: dict[str, list[int]] = {
    'numeric'      : [10, 12, 14],
    'alphanumeric' : [9, 11, 13],
    'byte'         : [8, 16, 16],
    'kanji'        : [8, 10, 12],
}


def char_count_bits(mode: str, version: int) -> int:
    if version <= 9:
        group = 0
    elif version <= 26:
        group = 1
    else:
        group = 2
    return CHAR_COUNT_BITS[mode][group]
