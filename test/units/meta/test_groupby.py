from .. import TestUnitBase
from refinery.lib.loader import load_pipeline as L


class TestGroupBy(TestUnitBase):

    def test_01(self):
        pipeline = L('emit FOO BAR BAZ [| put k c:0 | groupby k [| sep - ]| sep : ]')
        self.assertEqual(pipeline(), B'FOO:BAR-BAZ')

    def test_hidden_chunk_with_the_same_value_is_not_grouped(self):
        pipeline = L(
            'emit FOO [| put g 1 | push [| chop 1 | groupby g [| cca . ]| pop a ]| pf {}{a} ]')
        self.assertEqual(pipeline(), B'FOOF.O.O.')
