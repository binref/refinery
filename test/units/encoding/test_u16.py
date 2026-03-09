from .. import TestUnitBase


class TestU16(TestUnitBase):

    def test_decode_utf16le_with_bom(self):
        unit = self.load()
        data = b'\xFF\xFEH\x00e\x00l\x00l\x00o\x00'
        self.assertEqual(unit(data), b'Hello')

    def test_encode_to_utf16le(self):
        unit = self.load()
        data = b'Hello'
        self.assertEqual(data | -unit | bytes, b'H\x00e\x00l\x00l\x00o\x00')

    def test_roundtrip(self):
        unit = self.load()
        data = b'Test Data'
        encoded = data | -unit | bytes
        self.assertEqual(unit(b'\xFF\xFE' + encoded), data)

    def test_empty_input(self):
        unit = self.load()
        self.assertEqual(unit.reverse(b''), b'')

    def test_decode_utf16be_with_bom(self):
        unit = self.load()
        data = b'\xFE\xFF\x00H\x00e\x00l\x00l\x00o'
        self.assertEqual(unit(data), b'Hello')

    def test_encode_single_character(self):
        unit = self.load()
        data = b'A'
        self.assertEqual(data | -unit | bytes, b'A\x00')

    def test_decode_single_character_with_bom(self):
        unit = self.load()
        data = b'\xFF\xFEA\x00'
        self.assertEqual(unit(data), b'A')

    def test_roundtrip_longer_string(self):
        unit = self.load()
        data = b'The Binary Refinery'
        encoded = data | -unit | bytes
        decoded = unit(b'\xFF\xFE' + encoded)
        self.assertEqual(decoded, data)

    def test_encode_digits(self):
        unit = self.load()
        data = b'0123456789'
        result = data | -unit | bytes
        self.assertEqual(result, b'0\x001\x002\x003\x004\x005\x006\x007\x008\x009\x00')

    def test_decode_without_bom_assumes_le(self):
        unit = self.load()
        data = b'H\x00i\x00'
        self.assertEqual(unit(b'\xFF\xFE' + data), b'Hi')

    def test_encode_produces_no_bom(self):
        unit = self.load()
        data = b'Hi'
        result = data | -unit | bytes
        self.assertFalse(result.startswith(b'\xFF\xFE'))
        self.assertFalse(result.startswith(b'\xFE\xFF'))
        self.assertEqual(result, b'H\x00i\x00')

    def test_roundtrip_preserves_spaces(self):
        unit = self.load()
        data = b'hello world'
        encoded = data | -unit | bytes
        decoded = unit(b'\xFF\xFE' + encoded)
        self.assertEqual(decoded, data)

    def test_encode_output_length(self):
        unit = self.load()
        data = b'ABCD'
        result = data | -unit | bytes
        self.assertEqual(len(result), len(data) * 2)
