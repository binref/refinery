import ast

from test import TestBase
from refinery.lib.deobfuscation import (
    cautious_eval,
    cautious_eval_or_default,
    cautious_parse,
    names_in_expression,
    ExpressionParsingFailure,
)


class TestDeobfuscation(TestBase):

    def test_cautious_eval_simple(self):
        self.assertEqual(cautious_eval('2+3'), 5)

    def test_cautious_eval_bitwise(self):
        self.assertEqual(cautious_eval('0xFF^0x0F'), 0xF0)

    def test_cautious_eval_shift(self):
        self.assertEqual(cautious_eval('1<<8'), 256)

    def test_cautious_eval_hex(self):
        self.assertEqual(cautious_eval('0xDEAD'), 0xDEAD)

    def test_cautious_eval_size_limit(self):
        with self.assertRaises(ExpressionParsingFailure):
            cautious_eval('1+2+3+4', size_limit=3)

    def test_cautious_eval_forbidden_call(self):
        with self.assertRaises(ExpressionParsingFailure):
            cautious_eval('__import__("os")')

    def test_cautious_eval_or_default(self):
        self.assertEqual(cautious_eval_or_default('invalid!!!', default=42), 42)

    def test_cautious_eval_or_default_success(self):
        self.assertEqual(cautious_eval_or_default('10*2', default=0), 20)

    def test_cautious_parse_simple(self):
        result = cautious_parse('x+1')
        self.assertIsInstance(result, ast.Expression)

    def test_names_in_expression(self):
        tree = cautious_parse('x+y')
        result = names_in_expression(tree)
        self.assertIn('x', result.loaded)
        self.assertIn('y', result.loaded)
        self.assertEqual(len(result.stored), 0)

    def test_cautious_parse_with_environment(self):
        result = cautious_parse('N+1', environment={'N': 10})
        self.assertIsInstance(result, ast.Expression)
