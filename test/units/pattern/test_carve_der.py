from .. import TestUnitBase


class TestCarveDER(TestUnitBase):

    def test_carve_simple_sequence(self):
        unit = self.load()
        # DER-encoded SEQUENCE containing two INTEGERs: 1 and 2
        der = bytes.fromhex('3006020101020102')
        data = b'\x00\x00' + der + b'\x00\x00'
        results = data | unit | []
        self.assertTrue(len(results) >= 1)

    def test_no_der_found(self):
        unit = self.load()
        data = b'Just plain text without any DER sequences'
        results = data | unit | []
        self.assertEqual(len(results), 0)

    def test_skip_null_length(self):
        unit = self.load()
        # 0x30 followed by 0x00 should be skipped
        data = b'\x30\x00rest of data'
        results = data | unit | []
        self.assertEqual(len(results), 0)
