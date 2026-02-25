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
