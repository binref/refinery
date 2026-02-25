from .. import TestUnitBase


class TestJAMV(TestUnitBase):

    def test_simple(self):
        pl = self.load_pipeline('emit R ry The Bina efine [| jamv c{size} | pf {c3} {c4}{c2} {c1}{c5}{c2} ]')
        self.assertEqual(pl | str, 'The Binary Refinery')
