from ... import TestUnitBase


class TestROT(TestUnitBase):

    def test_fo8(self):
        unit = self.load(13)
        self.assertEqual(
            'This is gradually going to be harder and harder, just like FLARE-ON 8',
            str(B'Guvf vf tenqhnyyl tbvat gb or uneqre naq uneqre, whfg yvxr SYNER-BA 8' | unit)
        )
