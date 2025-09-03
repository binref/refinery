# flake8: noqa
from refinery.lib.loader import load_pipeline
from .. import TestUnitBase


class TestIfPattern(TestUnitBase):

    def test_simple_01(self):
        ps = BR'"C:\\work\\is\\fun\\"'.hex()
        result = load_pipeline(RF'emit H:{ps} | carve -d string [| iffp path ]')
        result = result()
        self.assertEqual(result, B'C:\\work\\is\\fun\\')
