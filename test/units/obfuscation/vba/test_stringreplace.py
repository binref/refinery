from ... import TestUnitBase


class TestStringReplace(TestUnitBase):

    def setUp(self):
        super().setUp()
        self.unit = self.load()

    def test_trivial(self):
        self.assertEqual(
            self.unit.deobfuscate(
                '''impairingsgutta = Replace("ADs@j|P3FODBs@j|P3F.Sts@j|P3Fs@j|P3Fs@j|P3Fream", "s@j|P3F", "")'''),
            'impairingsgutta = "ADODB.Stream"'
        )
