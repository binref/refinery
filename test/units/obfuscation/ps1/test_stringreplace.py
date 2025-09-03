from ... import TestUnitBase


class TestStringReplace(TestUnitBase):

    def setUp(self):
        super().setUp()
        self.unit = self.load()

    def test_trivial(self):
        self.assertEqual(
            self.unit.deobfuscate('''"Hello World".replace('l', "FOO")'''),
            '"HeFOOFOOo WorFOOd"'
        )

    def test_real_world_01(self):
        data = B'''"UVL0NR"-RepLaCe"UVL",""""-RepLaCe "0NR","'"-CrePLAcE  '31V',"|"))'''
        wish = B'''"""`'"))'''
        self.assertEqual(self.unit(data), wish)

    def test_variable_substitution_01(self):
        data = '''Write-Output "The $product costs `$100 for the average person." -replace '$', "€";'''.encode('utf8')
        wish = '''Write-Output "The $product costs €100 for the average person.";'''.encode('utf8')
        self.assertEqual(self.unit(data), wish)

    def test_variable_substitution_02(self):
        data = '''Write-Output "The $product costs `$100 for the average person." -replace '$', "$currency";'''.encode('utf8')
        wish = '''Write-Output "The $product costs ${currency}100 for the average person.";'''.encode('utf8')
        self.assertEqual(self.unit(data), wish)
