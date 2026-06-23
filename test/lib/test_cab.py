import random

from refinery.lib.cab import cab_data_checksum
from .. import TestBase


def _reference(content: bytes, checksum: int = 0) -> int:
    # The CAB data-block checksum is the XOR of all little-endian 32-bit words, XOR the
    # big-endian value of the trailing one to three bytes.
    n = len(content)
    for j in range(0, n - n % 4, 4):
        checksum ^= int.from_bytes(content[j:j + 4], 'little')
    if k := n % 4:
        checksum ^= int.from_bytes(content[-k:], 'big')
    return checksum


class TestCabChecksum(TestBase):

    def test_empty_returns_seed(self):
        self.assertEqual(cab_data_checksum(memoryview(B''), 0x12345678), 0x12345678)

    def test_single_word_little_endian(self):
        self.assertEqual(cab_data_checksum(memoryview(B'\x01\x02\x03\x04')), 0x04030201)

    def test_trailing_bytes_big_endian(self):
        self.assertEqual(cab_data_checksum(memoryview(B'\x01\x02\x03')), 0x010203)

    def test_word_and_tail(self):
        self.assertEqual(cab_data_checksum(memoryview(B'\x01\x02\x03\x04\x05')), 0x04030204)

    def test_matches_reference_for_many_lengths(self):
        rng = random.Random(0xC4B5)
        for n in (*range(0, 40), 255, 256, 257, 1023, 4096, 32767, 32768, 65535):
            data = bytes(rng.getrandbits(8) for _ in range(n))
            seed = rng.getrandbits(32)
            self.assertEqual(cab_data_checksum(memoryview(data), seed), _reference(data, seed))
