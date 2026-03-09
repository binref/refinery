from refinery.lib.rtfc import compress, decompress, _crc32
from .. import TestBase


class TestCRC32(TestBase):

    def test_known_payload(self):
        data = b'\x03\x00\n\x00rcpg125B2\n\xf3 hel\t\x00 bw\x05\xb0ld}\n\x80\x0f\xa0'
        self.assertEqual(_crc32(data), 0xA7C7C5F1)

    def test_empty(self):
        self.assertEqual(_crc32(b''), 0x00000000)


class TestDecompress(TestBase):

    TEST_C = b'-\0\0\0+\0\0\0LZFu\xf1\xc5\xc7\xa7\x03\0\n\0rcpg125B2\n\xf3 hel\t\0 bw\05\xb0ld}\n\x80\x0f\xa0'
    TEST_D = b'{\\rtf1\\ansi\\ansicpg1252\\pard hello world}\r\n'
    TEST_U = b'.\0\0\0"\0\0\0MELA\0\0\0\0{\\rtf1\\ansi\\ansicpg1252\\pard test}'

    def test_lzfu(self):
        self.assertEqual(decompress(self.TEST_C), self.TEST_D)

    def test_mela(self):
        self.assertEqual(decompress(self.TEST_U), b'{\\rtf1\\ansi\\ansicpg1252\\pard test}')

    def test_empty_data_raises(self):
        with self.assertRaises(ValueError):
            decompress(b'')

    def test_short_data_raises(self):
        with self.assertRaises(ValueError):
            decompress(b'0123456789abcde')

    def test_unknown_compression_type_raises(self):
        with self.assertRaises(ValueError):
            decompress(b'\x10\x00\x00\x00\x11\x00\x00\x00ABCD\xff\xff\xff\xff')

    def test_invalid_crc_raises(self):
        with self.assertRaises(ValueError):
            decompress(b'\x10\x00\x00\x00\x11\x00\x00\x00LZFu\xff\xff\xff\xff')


class TestCompress(TestBase):

    def test_lzfu(self):
        data = b'{\\rtf1\\ansi\\ansicpg1252\\pard hello world}\r\n'
        self.assertEqual(compress(data, compressed=True), TestDecompress.TEST_C)

    def test_mela(self):
        data = b'{\\rtf1\\ansi\\ansicpg1252\\pard hello world}\r\n'
        result = compress(data, compressed=False)
        self.assertEqual(result[8:12], b'MELA')
        self.assertEqual(int.from_bytes(result[12:16], 'little'), 0)
        self.assertEqual(result[16:], data)

    def test_repeated_tokens(self):
        data = b'{\\rtf1 WXYZWXYZWXYZWXYZWXYZ}'
        expected = b'\x1a\0\0\0\x1c\0\0\0LZFu\xe2\xd4KQA\0\04 WXYZ\rn}\01\x0e\xb0'
        self.assertEqual(compress(data), expected)


class TestRoundTrip(TestBase):

    def test_short(self):
        data = b'{\\rtf1\\ansi\\mac\\deff0\\deftab720'
        self.assertEqual(decompress(compress(data, compressed=True)), data)

    def test_longer_than_dict(self):
        data = b'{\\rtf1\\ansi\\ansicpg1252\\pard hello world'
        while len(data) < 4096:
            data += b'testtest'
        data += b'}'
        self.assertEqual(decompress(compress(data, compressed=True)), data)

    def test_memoryview_input(self):
        data = b'{\\rtf1\\ansi\\ansicpg1252\\pard memoryview test}\r\n'
        mv = memoryview(data)
        compressed = compress(mv, compressed=True)
        self.assertEqual(decompress(memoryview(compressed)), data)
