from .. import TestUnitBase


class TestXTW(TestUnitBase):

    def test_extract_bitcoin_address(self):
        unit = self.load()
        btc = b'1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'
        data = b'Send payment to ' + btc + b' please.'
        results = data | unit | []
        self.assertTrue(len(results) >= 1)
        self.assertIn(btc, b''.join(bytes(r) for r in results))

    def test_no_wallet_found(self):
        unit = self.load()
        data = b'This text contains no wallet addresses at all.'
        results = data | unit | []
        self.assertEqual(len(results), 0)
