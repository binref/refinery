from refinery.lib.loader import load_detached as L
from .. import TestUnitBase


class TestIfRex(TestUnitBase):

    def test_filter_identifier_letters(self):
        pl = L('emit range::256') | L('chop 1')[self.load('\\w')]
        self.assertEqual(pl(), B'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz')

    def test_negate(self):
        pl = self.load_pipeline('emit ab bc cb [| iffx -R .b ]')
        self.assertEqual(pl(), b'bc')

    def test_regression_retain_argument_recognized(self):
        pl = self.load_pipeline('emit w 9 9 t [| iffx -r [0-9] | sub 9 ]')
        self.assertEqual(pl(), b'w00t')
