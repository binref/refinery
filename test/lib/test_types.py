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


class TestUtilityTypes(TestBase):

    def test_isstream(self):
        from refinery.lib.types import isstream
        import io
        self.assertTrue(isstream(io.BytesIO()))
        self.assertFalse(isstream(42))
        self.assertFalse(isstream(b'hello'))

    def test_isbuffer(self):
        from refinery.lib.types import isbuffer
        self.assertTrue(isbuffer(b'hello'))
        self.assertTrue(isbuffer(bytearray(b'hello')))
        self.assertTrue(isbuffer(memoryview(b'hello')))
        self.assertFalse(isbuffer('hello'))
        self.assertFalse(isbuffer(42))

    def test_asbuffer(self):
        from refinery.lib.types import asbuffer
        self.assertIsNotNone(asbuffer(b'hello'))
        self.assertIsNotNone(asbuffer(bytearray(b'test')))
        self.assertIsNone(asbuffer('string'))
        self.assertIsNone(asbuffer(42))

    def test_typename(self):
        from refinery.lib.types import typename
        self.assertEqual(typename(42), 'int')
        self.assertEqual(typename('foo'), 'str')
        self.assertEqual(typename(b'foo'), 'bytes')
        self.assertEqual(typename(int), 'int')

    def test_convert(self):
        from refinery.lib.types import convert
        self.assertIsInstance(convert(42, str), str)
        self.assertEqual(convert(42, str), '42')
        self.assertIs(convert('hello', str), 'hello')

    def test_inf_inplace_arithmetic(self):
        Infty = INF()
        x = INF()
        x += 5
        self.assertIs(x, Infty)
        x -= 5
        self.assertIs(x, Infty)
        x *= 5
        self.assertIs(x, Infty)
        x %= 5
        self.assertIs(x, Infty)

    def test_inf_shift(self):
        Infty = INF()
        self.assertEqual(5 >> Infty, 0)
        self.assertEqual(5 << Infty, 0)

    def test_inf_format(self):
        Infty = INF()
        self.assertEqual(F'{Infty}', '∞')

    def test_ast_or(self):
        self.assertEqual(AST() | 42, 42)
        self.assertEqual(AST() | 'hello', 'hello')

    def test_repeated_integer(self):
        from refinery.lib.types import RepeatedInteger
        r = RepeatedInteger(7)
        self.assertEqual(int(r), 7)
        it = iter(r)
        self.assertEqual(next(it), 7)
        self.assertEqual(next(it), 7)
        self.assertEqual(next(it), 7)

    def test_no_default(self):
        from refinery.lib.types import NoDefault
        nd = NoDefault()
        self.assertIs(nd, NoDefault)

    def test_bounds_int(self):
        from refinery.lib.types import BoundsType
        b = BoundsType(5)
        self.assertIn(5, b)
        self.assertNotIn(4, b)
        self.assertNotIn(6, b)

    def test_bounds_slice(self):
        from refinery.lib.types import bounds
        b = bounds[2:8]
        self.assertIn(2, b)
        self.assertIn(5, b)
        self.assertIn(8, b)
        self.assertNotIn(1, b)
        self.assertNotIn(9, b)

    def test_bounds_slice_step(self):
        from refinery.lib.types import bounds
        b = bounds[0:10:2]
        self.assertIn(0, b)
        self.assertIn(2, b)
        self.assertIn(4, b)
        self.assertNotIn(1, b)
        self.assertNotIn(3, b)

    def test_bounds_iter(self):
        from refinery.lib.types import bounds
        b = bounds[1:5]
        self.assertEqual(list(b), [1, 2, 3, 4, 5])

    def test_bounds_repr(self):
        from refinery.lib.types import bounds
        b = bounds[1:5:2]
        self.assertEqual(repr(b), '[1:5:2]')

    def test_bounds_error_negative_step(self):
        from refinery.lib.types import BoundsType
        with self.assertRaises(ValueError):
            BoundsType(slice(0, 10, -1))

    def test_bounds_error_max_lt_min(self):
        from refinery.lib.types import BoundsType
        with self.assertRaises(ValueError):
            BoundsType(slice(10, 5))
