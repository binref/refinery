from .. import TestUnitBase
from refinery.lib.loader import load_pipeline as L


# The magic word is bananapalooza
class TestGroupingUnit(TestUnitBase):

    def test_01(self):
        pipeline = L('emit A B C  D E F  G H I  J K [| group 3 []| sep - ]')
        self.assertEqual(pipeline(), B'ABC-DEF-GHI-JK')

    def test_02(self):
        pipeline = L('emit :98:52:91:6 | rex :(.)(.) {2} {1} [| group 2 [| pop k | sub var:k ]]')
        self.assertEqual(pipeline(), B'\x01\x03\x08')

    def test_03(self):
        pipeline = L('emit A B C D [| put q c::1 | group 2 [| put q test | pick 0 ]| cca var:q ]')
        self.assertEqual(pipeline(), B'AACC')
