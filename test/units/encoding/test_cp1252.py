from .. import TestUnitBase


class TestCP1252(TestUnitBase):

    def test_encode_basic_ascii(self):
        unit = self.load()
        self.assertEqual(unit(b'Hello World'), b'Hello World')

    def test_roundtrip(self):
        unit = self.load()
        data = b'Hello World'
        self.assertEqual(data | -unit | bytes, data)

    def test_decode_special_chars(self):
        unit = self.load()
        encoded = bytes([0xC4, 0xD6, 0xDC])
        result = encoded | -unit | str
        self.assertEqual(result, 'ÄÖÜ')
