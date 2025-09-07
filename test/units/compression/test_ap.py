from .. import TestUnitBase


class TestAPLib(TestUnitBase):

    def test_decompress_kevin(self):
        unit = self.load()
        data = bytes.fromhex('4B006576696E277320673A6F74727D68E86D7A613B6963392D77296E64104820682C982E00')
        self.assertEqual(
            b"Kevin's got the magic - and the magic's got Kevin.",
            unit(data)
        )

    def test_packed_with_dipper(self):
        data = self.download_sample('ad320839e01df160c5feb0e89131521719a65ab11c952f33e03d802ecee3f51f')
        data = data | self.load_pipeline(
            'vsnip 0x01011240:0x1e348 | rex ..(..) {1} []| alu -B4 L(B@0x26FE,4)+0x77777778'
        ) | bytes
        unit = self.load()
        test = data | unit | self.ldu('sha256', text=True) | str
        self.assertEqual(test, 'f31468c95437a0c99be5551536b64576e21eeacfd43b0c63b020cdc10465a01b')
