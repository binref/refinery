# flake8: noqa
from refinery.lib.loader import load_detached as L
from .. import TestUnitBase


class TestIfCount(TestUnitBase):

    def test_simple_01(self):
        cmd = 'emit The Binary Refinery is cool!'
        pl = L(cmd) [ self.load('6:') ]
        self.assertEqual(pl(), B'BinaryRefinery')
        pl = L(cmd) [ self.load('6') ]
        self.assertEqual(pl(), B'Binary')
        pl = L(cmd) [ self.load(':5') ]
        self.assertEqual(pl(), B'Theiscool!')
