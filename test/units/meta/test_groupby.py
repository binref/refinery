from .. import TestUnitBase
from refinery.lib.loader import load_pipeline as L


class TestGroupBy(TestUnitBase):

    def test_01(self):
        pipeline = L('emit FOO BAR BAZ [| put k c:0 | groupby k [| sep - ]| sep : ]')
        self.assertEqual(pipeline(), B'FOO:BAR-BAZ')
