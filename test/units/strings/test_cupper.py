from .. import TestUnitBase


class TestCUpper(TestUnitBase):

    def test_simple_01(self):
        unit = self.load()
        data = B'That is not dead which can eternal lie, And with strange aeons even death may die.'
        wish = B'THAT IS NOT DEAD WHICH CAN ETERNAL LIE, AND WITH STRANGE AEONS EVEN DEATH MAY DIE.'
        self.assertEqual(bytes(data | unit), wish)
