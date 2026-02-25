from .. import TestBase
from refinery.lib.types import INF, AST


class TestSingletonTypes(TestBase):

    def test_inf_comparisons(self):
        Infty = INF()
        self.assertFalse(Infty < 5)
        self.assertFalse(Infty < 1000000)
        self.assertFalse(Infty <= 5)
        self.assertTrue(Infty > 5)
        self.assertTrue(Infty > 1000000)
        self.assertTrue(Infty >= 5)
        self.assertTrue(Infty == Infty)
        self.assertFalse(Infty == 5)
        self.assertIsNone(abs(Infty))

    def test_inf_reverse_comparisons(self):
        Infty = INF()
        self.assertTrue(5 < Infty)
        self.assertTrue(1000000 < Infty)
        self.assertTrue(5 <= Infty)
        self.assertFalse(5 > Infty)
        self.assertFalse(1000000 > Infty)
        self.assertFalse(5 >= Infty)

    def test_inf_arithmetic(self):
        Infty = INF()
        self.assertIs(Infty + 5, Infty)
        self.assertIs(5 + Infty, Infty)
        self.assertIs(Infty * 2, Infty)
        self.assertIs(2 * Infty, Infty)
        self.assertIs(Infty - 5, Infty)
        self.assertIs(Infty / 2, Infty)
        self.assertIs(Infty // 2, Infty)
        self.assertIs(Infty % 2, Infty)
        self.assertIs(Infty ** 2, Infty)

    def test_inf_repr(self):
        Infty = INF()
        self.assertEqual(repr(Infty), '∞')
        self.assertEqual(str(Infty), '∞')

    def test_ast_equality(self):
        A = AST()
        self.assertTrue(A == 5)
        self.assertTrue(A == 'hello')
        self.assertTrue(A == [1, 2, 3])
        self.assertTrue(A == None)
        self.assertFalse(A != 5)
        self.assertFalse(A != 'hello')

    def test_ast_contains(self):
        A = AST()
        self.assertTrue(5 in A)
        self.assertTrue('hello' in A)
        self.assertTrue([1, 2, 3] in A)

    def test_ast_repr(self):
        self.assertEqual(repr(AST()), '*')

    def test_nomask_bitwise(self):
        NM = -1
        self.assertEqual(NM & 0xFF, 0xFF)
        self.assertEqual(0xFF & NM, 0xFF)
        self.assertEqual(NM & 0x1234, 0x1234)
        self.assertEqual(0x1234 & NM, 0x1234)
