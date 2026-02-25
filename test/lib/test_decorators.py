from .. import TestBase

from refinery.lib.decorators import masked


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
