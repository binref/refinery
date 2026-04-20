from .. import TestUnitBase
from . import KADATH1, KADATH2

import pytest


@pytest.mark.cythonized
class TEstLZJB(TestUnitBase):

    def test_simple_invertible_01(self):
        unit = self.load()
        self.assertEqual(KADATH1 | -unit | unit | str, KADATH1)

    def test_simple_invertible_02(self):
        unit = self.load()
        self.assertEqual(KADATH2 | -unit | unit | str, KADATH2)

    def test_overlapping_backreference(self):
        """
        Regression test: overlapping back-reference copies must repeat
        the pattern correctly, not produce zero-filled gaps.
        """
        unit = self.load()
        data = b'ABCABC' * 100
        self.assertEqual(data | -unit | unit | bytes, data)
