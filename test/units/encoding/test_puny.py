from .. import TestUnitBase


class TestPunycode(TestUnitBase):

    def test_decode_idna(self):
        unit = self.load()
        result = b'xn--mnchen-3ya.de' | unit | bytes
        self.assertEqual(result, 'münchen.de'.encode('utf-8'))

    def test_encode_idna(self):
        unit = self.load()
        result = 'münchen.de'.encode('utf-8') | -unit | bytes
        self.assertEqual(result, b'xn--mnchen-3ya.de')

    def test_roundtrip_idna(self):
        unit = self.load()
        original = 'münchen.de'.encode('utf-8')
        self.assertEqual(original | -unit | unit | bytes, original)

    def test_raw_punycode_decode(self):
        unit = self.load(raw=True)
        result = b'mnchen-3ya' | unit | bytes
        self.assertEqual(result, 'münchen'.encode('utf-8'))

    def test_raw_punycode_encode(self):
        unit = self.load(raw=True)
        result = 'münchen'.encode('utf-8') | -unit | bytes
        self.assertEqual(result, b'mnchen-3ya')

    def test_roundtrip_raw(self):
        unit = self.load(raw=True)
        original = 'münchen'.encode('utf-8')
        self.assertEqual(original | -unit | unit | bytes, original)

    def test_ascii_passthrough_raw(self):
        unit = self.load(raw=True)
        data = b'example'
        result = data | -unit | bytes
        self.assertEqual(result, b'example-')
