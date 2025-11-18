from .. import TestUnitBase
from . import KADATH1, KADATH2


class TEstLZJB(TestUnitBase):

    def test_simple_invertible_01(self):
        unit = self.load()
        self.assertEqual(KADATH1 | -unit | unit | str, KADATH1)

    def test_simple_invertible_02(self):
        unit = self.load()
        self.assertEqual(KADATH2 | -unit | unit | str, KADATH2)
