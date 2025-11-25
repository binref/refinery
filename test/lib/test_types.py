from .. import TestBase
from refinery.lib.types import INF, AST, NoMask


class TestSingletonTypes(TestBase):

    def test_inf_comparisons(self):
        self.assertFalse(INF < 5)
        self.assertFalse(INF < 1000000)
        self.assertFalse(INF <= 5)
        self.assertTrue(INF > 5)
        self.assertTrue(INF > 1000000)
        self.assertTrue(INF >= 5)
        self.assertTrue(INF == INF)
        self.assertFalse(INF == 5)
        self.assertIsNone(abs(INF))

    def test_inf_reverse_comparisons(self):
        self.assertTrue(5 < INF)
        self.assertTrue(1000000 < INF)
        self.assertTrue(5 <= INF)
        self.assertFalse(5 > INF)
        self.assertFalse(1000000 > INF)
        self.assertFalse(5 >= INF)

    def test_inf_arithmetic(self):
        self.assertIs(INF + 5, INF)
        self.assertIs(5 + INF, INF)
        self.assertIs(INF * 2, INF)
        self.assertIs(2 * INF, INF)
        self.assertIs(INF - 5, INF)
        self.assertIs(INF / 2, INF)
        self.assertIs(INF // 2, INF)
        self.assertIs(INF % 2, INF)
        self.assertIs(INF ** 2, INF)

    def test_inf_repr(self):
        self.assertEqual(repr(INF), '∞')
        self.assertEqual(str(INF), '∞')

    def test_ast_equality(self):
        self.assertTrue(AST == 5)
        self.assertTrue(AST == 'hello')
        self.assertTrue(AST == [1, 2, 3])
        self.assertTrue(AST == None)
        self.assertFalse(AST != 5)
        self.assertFalse(AST != 'hello')

    def test_ast_contains(self):
        self.assertTrue(5 in AST)
        self.assertTrue('hello' in AST)
        self.assertTrue([1, 2, 3] in AST)

    def test_ast_repr(self):
        self.assertEqual(repr(AST), '*')

    def test_nomask_bitwise(self):
        self.assertEqual(NoMask & 0xFF, 0xFF)
        self.assertEqual(0xFF & NoMask, 0xFF)
        self.assertEqual(NoMask & 0x1234, 0x1234)
        self.assertEqual(0x1234 & NoMask, 0x1234)

    def test_singleton_instantiation(self):
        from refinery.lib.types import _INF, _AST, _NoMask
        self.assertIs(_INF(), _INF)
        self.assertIs(_AST(), _AST)
        self.assertIs(_NoMask(), _NoMask)
