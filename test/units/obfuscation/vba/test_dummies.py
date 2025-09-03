from ... import TestUnitBase


class TestDummyVariableRemover(TestUnitBase):

    def setUp(self):
        super().setUp()
        self.unit = self.load()

    def test_overeager_removal_regression_01(self):
        data = 'a.Close\nb = z.function(x)\n'
        self.assertEqual(self.unit.deobfuscate(data).strip(), data.strip())
