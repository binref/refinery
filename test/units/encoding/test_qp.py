from .. import TestUnitBase


class TestQuotedPrintable(TestUnitBase):

    def test_decode_basic(self):
        unit = self.load()
        encoded = b'Hello=20World'
        self.assertEqual(encoded | unit | bytes, b'Hello World')

    def test_encode_basic(self):
        unit = self.load()
        data = b'Hello World'
        encoded = data | -unit | bytes
        # quopri encodes tab and space before newline, but plain spaces
        # in the middle of a line are left alone
        self.assertIn(b'Hello World', encoded)

    def test_roundtrip(self):
        unit = self.load()
        data = b'The quick brown fox = lazy dog'
        result = data | -unit | unit | bytes
        self.assertEqual(data, result)

    def test_decode_special_chars(self):
        unit = self.load()
        encoded = b'=C3=BC'
        expected = bytes([0xC3, 0xBC])
        self.assertEqual(encoded | unit | bytes, expected)

    def test_encode_special_chars(self):
        unit = self.load()
        data = bytes([0xC3, 0xBC])
        encoded = data | -unit | bytes
        self.assertIn(b'=C3=BC', encoded)

    def test_soft_line_break(self):
        unit = self.load()
        encoded = b'soft=\r\nbreak'
        self.assertEqual(encoded | unit | bytes, b'softbreak')

    def test_roundtrip_binary(self):
        unit = self.load()
        data = bytes(range(256))
        result = data | -unit | unit | bytes
        self.assertEqual(data, result)
