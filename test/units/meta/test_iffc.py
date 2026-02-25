# flake8: noqa
from refinery.lib.loader import load_detached as L
from .. import TestUnitBase


class TestIfCount(TestUnitBase):

    def test_simple_01(self):
        pl = L('emit The Binary Refinery is cool!') [ self.load('6:') ]
        self.assertEqual(pl(), B'BinaryRefinery')
