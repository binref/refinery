from .. import TestUnitBase


class TestHex(TestUnitBase):

    def test_decode_hex(self):
        unit = self.load()
        self.assertEqual(unit(b'48656C6C6F'), b'Hello')

    def test_decode_lowercase(self):
        unit = self.load()
        self.assertEqual(unit(b'48656c6c6f'), b'Hello')

    def test_encode_hex(self):
        unit = self.load()
        self.assertEqual(b'Hello' | -unit | bytes, b'48656C6C6F')

    def test_strips_non_hex_chars(self):
        unit = self.load()
        self.assertEqual(unit(b'48 65 6C 6C 6F'), b'Hello')

    def test_odd_length_strips_trailing(self):
        unit = self.load()
        self.assertEqual(unit(b'48656C6C6F0'), b'Hello')

    def test_roundtrip(self):
        unit = self.load()
        data = b'\x00\x01\x02\xFE\xFF'
        self.assertEqual(data | -unit | bytes, data)
