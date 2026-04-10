from .. import TestUnitBase


class TestBigIntUnit(TestUnitBase):

    def test_inversion_base_02e(self):
        unit = self.load('-e', '2')
        data = self.generate_random_buffer(24)
        self.assertEqual(data, unit.process(unit.reverse(data)))

    def test_inversion_base_02E(self):
        unit = self.load('2')
        data = self.generate_random_buffer(24)
        self.assertEqual(data, unit.process(unit.reverse(data)))

    def test_inversion_base_10(self):
        unit = self.load('10')
        data = self.generate_random_buffer(24)
        self.assertEqual(data, unit.process(unit.reverse(data)))

    def test_inversion_base_16re(self):
        unit = self.load()
        data = B'0xBAADF00DC0FFEEBABE'
        self.assertEqual(data, unit.reverse(unit.process(data)))

    def test_inversion_base_16(self):
        unit = self.load('0x10')
        data = B'BAADF00DC0FFEEBABE'
        self.assertEqual(data, unit.reverse(unit.process(data)))

    def test_invalid_base_values(self):
        with self.assertRaises(ValueError):
            B'0' | self.load(1) | ...
        with self.assertRaises(ValueError):
            B'0' | self.load(38) | ...
        with self.assertRaises(ValueError):
            B'0' | self.load(-2) | ...

    def test_hardcoded_example_base_36(self):
        unit = self.load(36)
        data = B'BINARYREFINERY'
        self.assertEqual(data, unit.reverse(unit.process(data)))

    def test_small_alphabet(self):
        alphabet = b'abc'
        data = 'cbac'
        unit = self.load(alphabet)
        self.assertEqual(bytes(data | unit), b'A')

    def test_small_alphabet_autocase(self):
        alphabet = b'ABC'
        data = 'cbac'
        unit = self.load(alphabet)
        self.assertEqual(bytes(data | unit), b'A')

    def test_regression_base36(self):
        data = b'5114678'
        test = data | self.load(36) | -self.load(36, strip_padding=True) | bytes
        self.assertEqual(test, data)

    def test_empty_decodes_as_empty(self):
        for b in (2, 7, 12, 203):
            data = B''
            test = data | self.load(b) | bytes
            self.assertEqual(data, test)
