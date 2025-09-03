from .. import TestUnitBase


class TestAPLib(TestUnitBase):

    def test_decompress_kevin(self):
        unit = self.load()
        data = bytes.fromhex('4B006576696E277320673A6F74727D68E86D7A613B6963392D77296E64104820682C982E00')
        self.assertEqual(
            b"Kevin's got the magic - and the magic's got Kevin.",
            unit(data)
        )
