from .. import TestUnitBase

import pytest


@pytest.mark.cythonized
class TestA3Xs(TestUnitBase):

    def test_ea05(self):
        sample = self.download_sample(
            '9b66a8ea0f1c64965b06e7a45afbe56f2d4e6d5ef65f32446defccbebe730813')
        out = sample | self.load() | str
        self.assertIn(
            r'C:\Users\johnh\Desktop\Desktop\otto_calculator.au3', out)
