import itertools

from refinery.lib.inline import iterspread

from .. import TestBase


class TestIterSpread(TestBase):

    def test_simple_01(self):
        def test(a, b, c):
            return a + b - c
        inlined = iterspread(test, range(10, 16), itertools.count(), 5)
        result = list(inlined(None))
        self.assertListEqual(result, [5, 7, 9, 11, 13, 15])

    def test_varargs(self):
        class cls:
            def test(self, a, b, *value):
                f, g = value
                return self.value + a + b - (f * g)
            value = 100
        obj = cls()
        inlined = iterspread(obj.test, range(4), 100, itertools.count(), itertools.count())
        result = list(inlined(obj))
        self.assertListEqual(result, [200, 200, 198, 194])

    def test_empty_varargs(self):
        class cls:
            def test(self, a, b, *c):
                r = self.value + a + b
                for k in c:
                    r -= k
                return r
            value = 100
        obj = cls()
        inlined = iterspread(obj.test, range(4), 100)
        result = list(inlined(obj))
        self.assertListEqual(result, [200, 201, 202, 203])

    def test_masked(self):
        def test(a, b): return a - b
        inlined = bytes(iterspread(test, range(0x10), 0x55, mask=0xFF)(None))
        self.assertEqual(inlined, bytes(b - 0x55 & 0xFF for b in range(0x10)))

    def test_reserved_names_unbound(self):
        def test(a, b):
            return a - abs(b)
        inlined = bytes(iterspread(test, range(0x10), -0x55, mask=0xFF)(None))
        self.assertEqual(inlined, bytes(b - 0x55 & 0xFF for b in range(0x10)))

    def test_reserved_names_bound(self):
        class cls:
            def __init__(self):
                def test(a, b):
                    return self.value + a - abs(b)
                self.test = test
            value = 100
        obj = cls()
        inlined = bytes(iterspread(obj.test, range(0x10), -0x55, mask=0xFF)(obj))
        self.assertEqual(inlined, bytes(b + 100 - 0x55 & 0xFF for b in range(0x10)))
