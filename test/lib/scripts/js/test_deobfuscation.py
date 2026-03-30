from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.js.deobfuscation import deobfuscate
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer


class TestJsDeobfuscator(TestBase):

    def _deobfuscate(self, source: str) -> str:
        ast = JsParser(source).parse()
        deobfuscate(ast)
        return JsSynthesizer().convert(ast)

    def test_string_concat_simple(self):
        result = self._deobfuscate("'a' + 'b';")
        self.assertIn("'ab'", result)

    def test_string_concat_nested(self):
        result = self._deobfuscate("'a' + 'b' + 'c';")
        self.assertIn("'abc'", result)

    def test_arithmetic_add(self):
        result = self._deobfuscate('2 + 3;')
        self.assertIn('5', result)

    def test_arithmetic_multiply(self):
        result = self._deobfuscate('10 * 2;')
        self.assertIn('20', result)

    def test_arithmetic_subtract(self):
        result = self._deobfuscate('10 - 3;')
        self.assertIn('7', result)

    def test_arithmetic_power(self):
        result = self._deobfuscate('2 ** 3;')
        self.assertIn('8', result)

    def test_arithmetic_modulo(self):
        result = self._deobfuscate('10 % 3;')
        self.assertIn('1', result)

    def test_arithmetic_bitwise_or(self):
        result = self._deobfuscate('5 | 3;')
        self.assertIn('7', result)

    def test_arithmetic_bitwise_and(self):
        result = self._deobfuscate('5 & 3;')
        self.assertIn('1', result)

    def test_arithmetic_bitwise_xor(self):
        result = self._deobfuscate('5 ^ 3;')
        self.assertIn('6', result)

    def test_arithmetic_left_shift(self):
        result = self._deobfuscate('1 << 3;')
        self.assertIn('8', result)

    def test_arithmetic_right_shift(self):
        result = self._deobfuscate('8 >> 2;')
        self.assertIn('2', result)

    def test_arithmetic_unsigned_right_shift(self):
        result = self._deobfuscate('(-1) >>> 0;')
        self.assertIn('4294967295', result)

    def test_arithmetic_division_by_zero_unchanged(self):
        result = self._deobfuscate('1 / 0;')
        self.assertIn('/', result)

    def test_tuple_all_literals(self):
        result = self._deobfuscate('("a", "b", "c");')
        self.assertIn('"c"', result)
        self.assertNotIn('"a"', result)

    def test_tuple_non_literal_unchanged(self):
        result = self._deobfuscate('("a", x, "c");')
        self.assertIn('x', result)

    def test_array_indexing(self):
        result = self._deobfuscate('["a", "b", "c"][1];')
        self.assertIn('"b"', result)

    def test_array_indexing_first(self):
        result = self._deobfuscate('["x", "y"][0];')
        self.assertIn('"x"', result)

    def test_bracket_to_dot(self):
        result = self._deobfuscate('obj["prop"];')
        self.assertIn('obj.prop', result)

    def test_bracket_non_identifier_unchanged(self):
        result = self._deobfuscate('obj["a-b"];')
        self.assertIn('"a-b"', result)

    def test_bracket_reserved_word_unchanged(self):
        result = self._deobfuscate('obj["class"];')
        self.assertIn('"class"', result)

    def test_paren_unwrap_string(self):
        result = self._deobfuscate('("hello");')
        self.assertIn('hello', result)
        self.assertNotIn('(', result.replace('"hello"', '').replace("'hello'", ''))

    def test_paren_unwrap_number(self):
        result = self._deobfuscate('(42);')
        self.assertIn('42', result)

    def test_unary_not_zero(self):
        result = self._deobfuscate('!0;')
        self.assertIn('true', result)

    def test_unary_not_one(self):
        result = self._deobfuscate('!1;')
        self.assertIn('false', result)

    def test_void_zero(self):
        result = self._deobfuscate('void 0;')
        self.assertIn('undefined', result)

    def test_typeof_string(self):
        result = self._deobfuscate('typeof "x";')
        self.assertIn("'string'", result)

    def test_typeof_number(self):
        result = self._deobfuscate('typeof 42;')
        self.assertIn("'number'", result)

    def test_typeof_boolean(self):
        result = self._deobfuscate('typeof true;')
        self.assertIn("'boolean'", result)

    def test_unary_negate(self):
        result = self._deobfuscate('-(5);')
        self.assertIn('-5', result)

    def test_unary_plus(self):
        result = self._deobfuscate('+(5);')
        self.assertIn('5', result)

    def test_non_constant_unchanged(self):
        result = self._deobfuscate('a + b;')
        self.assertIn('a + b', result)

    def test_non_constant_member_unchanged(self):
        result = self._deobfuscate('a[b];')
        self.assertIn('a[b]', result)

    def test_combined_deobfuscation(self):
        result = self._deobfuscate('var x = "hel" + "lo"; var y = [1, 2, 3][0];')
        self.assertIn("'hello'", result)
        self.assertIn('1', result)
