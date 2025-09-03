from ... import TestUnitBase


class TestXTEA(TestUnitBase):

    def test_example_little_endian(self):
        data = bytes.fromhex('a3bab9180f2ff58eb6d5bfe356fc2b436c9ae1338fee4cb70b626fd037e4a797')
        unit = self.load(key=b'0123456789abcdef')
        self.assertEqual(data | unit | str, 'This is a secret message.')

    def test_example_big_endian(self):
        data = bytes.fromhex('eb7a1e2fe4de2699978ddfcec5bdd3649d654c0a7bc1c5c8b343cd8763afc883')
        unit = self.load(key=b'0123456789abcdef', swap=True)
        self.assertEqual(data | unit | str, 'This is a secret message.')
