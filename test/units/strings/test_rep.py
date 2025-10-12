from .. import TestUnitBase


class TestRep(TestUnitBase):

    def test_batman(self):
        unit = self.load('16', '[]')
        self.assertEqual(B'Na' | unit | bytes, B'NaNaNaNaNaNaNaNaNaNaNaNaNaNaNaNa')

    def test_sequence(self):
        unit = self.load('range:4:7', 't')
        self.assertListEqual(list(chunk['t'] for chunk in B"" | unit), list(range(4, 7)))

    def __test_variables_are_known_in_prefix(self):
        test = 0 | self.load_pipeline('put a ref [| put b rep[e:len(a)]:$ | pf {a}{b} ]') | str
        self.assertEqual(test, 'ref$$$')
