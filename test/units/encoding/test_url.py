from .. import TestUnitBase


class TestURLDecoder(TestUnitBase):

    def test_plus_decoding(self):
        unit = self.load(plus=True)
        self.assertEqual(b'1+%2B+2+=+%33' | +unit | bytes, b'1 + 2 = 3')
        self.assertEqual(b'1 + 2 = 3' | -unit | bytes, b'1+%2B+2+=+3')

    def test_hex(self):
        unit = self.load(hex=True)
        self.assertEqual(b'123' | -unit | bytes, b'%31%32%33')
