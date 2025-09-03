from ... import TestUnitBase


class TestPs1Typecast(TestUnitBase):

    def setUp(self):
        super().setUp()
        self.unit = self.load()

    def test_useless_string_cast(self):
        self.assertEqual(
            self.unit.deobfuscate('''.replAce(("M0I"),[strIng]"'")'''),
            '''.replAce(("M0I"),"'")'''
        )
