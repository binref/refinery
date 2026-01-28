# flake8: noqa
from refinery.lib.loader import load_detached as L
from .. import TestUnitBase


class TestIfStr(TestUnitBase):

    def test_simple_01(self):
        pl = L('emit raffle waffle rattle battle cattle settle') [ self.load('att') ]
        self.assertEqual(pl(), B'rattlebattlecattle')

    def test_nocase_01(self):
        pl = L('emit raffle WAFFLE rattle BATTLE cattle settle') [ self.load('bat', nocase=True) ]
        self.assertEqual(pl(), B'BATTLE')

    def test_nocase_02(self):
        pl = L('emit raffle WAFFLE rattle BATTLE cattle settle') [ self.load('bat') ]
        self.assertEqual(pl(), B'')
