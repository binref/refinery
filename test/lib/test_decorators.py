from .. import TestBase

from refinery.lib.decorators import masked

GLOBAL_CONSTANT1 = 0xBAAD


class TestDecorators(TestBase):

    def test_masking_16bit(self):
        @masked(0xFFFF)
        def add(a: int, b: int):
            return a + b

        self.assertEqual(add(0xFFFF, 1 + 0xBAD), 0xBAD)
        self.assertEqual(add(3, 4), 7)
        self.assertEqual(add(3, -4), 0xFFFF)

    def test_modulo_16bit(self):
        @masked(0x10000, mod=True)
        def add(a: int, b: int):
            return a + b

        self.assertEqual(add(0xFFFF, 1 + 0xBAD), 0xBAD)
        self.assertEqual(add(3, 4), 7)
        self.assertEqual(add(3, -4), 0xFFFF)

    def test_masking_with_bound_local_variable(self):
        @masked(0xFFFF)
        def foo(a: int):
            return a * local_constant

        local_constant = 99

        self.assertEqual(foo(0x1234), 2588)

    def test_masking_with_bound_global_variable(self):
        @masked(0xFFFFFF)
        def foo(a: int):
            return a * GLOBAL_CONSTANT1 + GLOBAL_CONSTANT2

        self.assertEqual(foo(0xDEFACED), 0x9cfe36)


GLOBAL_CONSTANT2 = 0xF00D


class TestDecoratorMaskedOps(TestBase):

    def test_masking_subtraction(self):
        @masked(0xFF)
        def sub(a: int, b: int):
            return a - b
        self.assertEqual(sub(5, 10), 251)

    def test_masking_multiplication(self):
        @masked(0xFF)
        def mul(a: int, b: int):
            return a * b
        self.assertEqual(mul(0x10, 0x10), 0)

    def test_masking_shift(self):
        @masked(0xFF)
        def shl(a: int, b: int):
            return a << b
        self.assertEqual(shl(1, 8), 0)
        self.assertEqual(shl(1, 7), 128)

    def test_masking_power(self):
        @masked(0xFFFF)
        def power(a: int, b: int):
            return a ** b
        self.assertEqual(power(0x100, 2), 0)
        self.assertEqual(power(3, 5), 243)

    def test_masking_augmented_assignment(self):
        @masked(0xFF)
        def augadd(a: int, b: int):
            a += b
            return a
        self.assertEqual(augadd(0xFF, 1), 0)

    def test_masking_unary_ops(self):
        @masked(0xFF)
        def negate(a: int):
            return -a
        result = negate(1)
        self.assertEqual(result & 0xFF, result)

    def test_wraps_without_annotations(self):
        from refinery.lib.decorators import wraps_without_annotations
        def original(a: int, b: str) -> bool:
            """Original doc."""
            pass

        @wraps_without_annotations(original)
        def wrapper(*args, **kwargs):
            pass

        self.assertEqual(wrapper.__name__, 'original')
        self.assertEqual(wrapper.__doc__, 'Original doc.')
        self.assertNotIn('a', wrapper.__annotations__)


class TestDecoratorMaskedAdvanced(TestBase):

    def test_masking_invert_unary(self):
        @masked(0xFF)
        def invert(a: int):
            return ~a
        result = invert(0)
        self.assertEqual(result & 0xFF, result)
        result2 = invert(0xFF)
        self.assertEqual(result2 & 0xFF, result2)

    def test_masking_right_shift_not_masked(self):
        @masked(0xFF)
        def shr(a: int, b: int):
            return a >> b
        self.assertEqual(shr(0x100, 1), 0x80)
        self.assertEqual(shr(0xFF, 4), 0x0F)

    def test_masking_division_not_masked(self):
        @masked(0xFF)
        def div(a: int, b: int):
            return a // b
        self.assertEqual(div(256, 2), 128)

    def test_masking_bitwise_and_not_masked(self):
        @masked(0xFF)
        def bitand(a: int, b: int):
            return a & b
        self.assertEqual(bitand(0xFFFF, 0x1234), 0x1234)

    def test_masking_preserves_function_name(self):
        @masked(0xFFFF)
        def my_special_function(x: int):
            return x + 1
        self.assertEqual(my_special_function.__name__, 'my_special_function')

    def test_masking_complex_expression(self):
        @masked(0xFF)
        def complex_op(a: int, b: int):
            c = a + b
            d = c * 2
            e = d - a
            return e
        result = complex_op(0x80, 0x90)
        self.assertEqual(result & 0xFF, result)

    def test_masking_augmented_sub(self):
        @masked(0xFF)
        def augsub(a: int, b: int):
            a -= b
            return a
        self.assertEqual(augsub(0, 1), 0xFF)

    def test_masking_augmented_mul(self):
        @masked(0xFF)
        def augmul(a: int, b: int):
            a *= b
            return a
        self.assertEqual(augmul(0x10, 0x10), 0)

    def test_masking_augmented_shift(self):
        @masked(0xFF)
        def augshl(a: int, b: int):
            a <<= b
            return a
        self.assertEqual(augshl(1, 8), 0)
        self.assertEqual(augshl(1, 7), 128)

    def test_masking_augmented_pow(self):
        @masked(0xFFFF)
        def augpow(a: int, b: int):
            a **= b
            return a
        self.assertEqual(augpow(0x100, 2), 0)
        self.assertEqual(augpow(3, 5), 243)

    def test_masking_negate_nonzero(self):
        @masked(0xFFFF)
        def neg(a: int):
            return -a
        self.assertEqual(neg(1) & 0xFFFF, neg(1))
        self.assertEqual(neg(0) & 0xFFFF, neg(0))

    def test_modulo_subtraction(self):
        @masked(0x100, mod=True)
        def sub(a: int, b: int):
            return a - b
        self.assertEqual(sub(5, 10), 251)

    def test_modulo_multiplication(self):
        @masked(0x100, mod=True)
        def mul(a: int, b: int):
            return a * b
        self.assertEqual(mul(0x10, 0x10), 0)

    def test_modulo_augmented_assignment(self):
        @masked(0x100, mod=True)
        def augadd(a: int, b: int):
            a += b
            return a
        self.assertEqual(augadd(0xFF, 1), 0)

    def test_masking_32bit(self):
        @masked(0xFFFFFFFF)
        def add32(a: int, b: int):
            return a + b
        self.assertEqual(add32(0xFFFFFFFF, 1), 0)
        self.assertEqual(add32(0x7FFFFFFF, 0x7FFFFFFF), 0xFFFFFFFE)

    def test_masking_zero_result(self):
        @masked(0xFF)
        def add(a: int, b: int):
            return a + b
        self.assertEqual(add(0x80, 0x80), 0)

    def test_masking_multiple_nested_closures(self):
        multiplier = 3
        offset = 7
        @masked(0xFF)
        def compute(x: int):
            return x * multiplier + offset
        result = compute(100)
        self.assertEqual(result & 0xFF, result)


class TestUnicodedDecorator(TestBase):

    def test_unicoded_basic_string_modification(self):
        from refinery.lib.decorators import unicoded

        class FakeUnit:
            codec = 'utf8'

        @unicoded
        def process(self, data):
            return data.upper()

        unit = FakeUnit()
        result = process(unit, b'hello world')
        self.assertEqual(result, b'HELLO WORLD')

    def test_unicoded_with_bytearray_input(self):
        from refinery.lib.decorators import unicoded

        class FakeUnit:
            codec = 'utf8'

        @unicoded
        def process(self, data):
            return data.replace('a', 'X')

        unit = FakeUnit()
        result = process(unit, bytearray(b'banana'))
        self.assertEqual(result, b'bXnXnX')

    def test_unicoded_preserves_empty_input(self):
        from refinery.lib.decorators import unicoded

        class FakeUnit:
            codec = 'utf8'

        @unicoded
        def process(self, data):
            return data

        unit = FakeUnit()
        result = process(unit, b'')
        self.assertEqual(result, b'')

    def test_unicoded_with_latin1_codec(self):
        from refinery.lib.decorators import unicoded

        class FakeUnit:
            codec = 'latin1'

        @unicoded
        def process(self, data):
            return data.upper()

        unit = FakeUnit()
        result = process(unit, 'caf\xe9'.encode('latin1'))
        expected = 'CAF\xc9'.encode('latin1')
        self.assertEqual(result, expected)
