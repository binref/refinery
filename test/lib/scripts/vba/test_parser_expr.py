from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.vba.parser import VbaParser
from refinery.lib.scripts.vba.model import (
    VbaBinaryExpression,
    VbaBooleanLiteral,
    VbaCallExpression,
    VbaDateLiteral,
    VbaEmptyLiteral,
    VbaFloatLiteral,
    VbaIdentifier,
    VbaIntegerLiteral,
    VbaMeExpression,
    VbaMemberAccess,
    VbaNewExpression,
    VbaNothingLiteral,
    VbaNullLiteral,
    VbaParenExpression,
    VbaStringLiteral,
    VbaTypeOfIsExpression,
    VbaUnaryExpression,
    VbaLetStatement,
)


class TestVbaParserExpressions(TestBase):

    def _parse_expr(self, source: str):
        code = F'x = {source}'
        ast = VbaParser(code).parse()
        self.assertTrue(len(ast.body) >= 1)
        stmt = ast.body[0]
        assert isinstance(stmt, VbaLetStatement)
        return stmt.value

    def test_integer_literal(self):
        expr = self._parse_expr('42')
        assert isinstance(expr, VbaIntegerLiteral)
        self.assertEqual(expr.value, 42)

    def test_hex_literal(self):
        expr = self._parse_expr('&HFF')
        assert isinstance(expr, VbaIntegerLiteral)
        self.assertEqual(expr.value, 255)

    def test_octal_literal(self):
        expr = self._parse_expr('&O77')
        assert isinstance(expr, VbaIntegerLiteral)
        self.assertEqual(expr.value, 63)

    def test_float_literal(self):
        expr = self._parse_expr('3.14')
        assert isinstance(expr, VbaFloatLiteral)
        self.assertAlmostEqual(expr.value, 3.14)

    def test_string_literal(self):
        expr = self._parse_expr('"Hello"')
        assert isinstance(expr, VbaStringLiteral)
        self.assertEqual(expr.value, 'Hello')

    def test_string_with_escaped_quote(self):
        expr = self._parse_expr('"He said ""hi"""')
        assert isinstance(expr, VbaStringLiteral)
        self.assertEqual(expr.value, 'He said "hi"')

    def test_boolean_true(self):
        expr = self._parse_expr('True')
        assert isinstance(expr, VbaBooleanLiteral)
        self.assertTrue(expr.value)

    def test_boolean_false(self):
        expr = self._parse_expr('False')
        assert isinstance(expr, VbaBooleanLiteral)
        self.assertFalse(expr.value)

    def test_nothing(self):
        code = 'Set x = Nothing'
        ast = VbaParser(code).parse()
        from refinery.lib.scripts.vba.model import VbaSetStatement
        stmt = ast.body[0]
        assert isinstance(stmt, VbaSetStatement)
        assert isinstance(stmt.value, VbaNothingLiteral)

    def test_null(self):
        expr = self._parse_expr('Null')
        assert isinstance(expr, VbaNullLiteral)

    def test_empty(self):
        expr = self._parse_expr('Empty')
        assert isinstance(expr, VbaEmptyLiteral)

    def test_me(self):
        expr = self._parse_expr('Me')
        assert isinstance(expr, VbaMeExpression)

    def test_date_literal(self):
        expr = self._parse_expr('#12/31/2024#')
        assert isinstance(expr, VbaDateLiteral)
        self.assertEqual(expr.raw, '#12/31/2024#')

    def test_addition(self):
        expr = self._parse_expr('1 + 2')
        assert isinstance(expr, VbaBinaryExpression)
        self.assertEqual(expr.operator, '+')

    def test_subtraction(self):
        expr = self._parse_expr('5 - 3')
        assert isinstance(expr, VbaBinaryExpression)
        self.assertEqual(expr.operator, '-')

    def test_multiplication(self):
        expr = self._parse_expr('2 * 3')
        assert isinstance(expr, VbaBinaryExpression)
        self.assertEqual(expr.operator, '*')

    def test_division(self):
        expr = self._parse_expr('10 / 3')
        assert isinstance(expr, VbaBinaryExpression)
        self.assertEqual(expr.operator, '/')

    def test_integer_division(self):
        expr = self._parse_expr('10 \\ 3')
        assert isinstance(expr, VbaBinaryExpression)
        self.assertEqual(expr.operator, '\\')

    def test_mod(self):
        expr = self._parse_expr('10 Mod 3')
        assert isinstance(expr, VbaBinaryExpression)
        self.assertEqual(expr.operator, 'Mod')

    def test_exponentiation(self):
        expr = self._parse_expr('2 ^ 3')
        assert isinstance(expr, VbaBinaryExpression)
        self.assertEqual(expr.operator, '^')

    def test_string_concat(self):
        expr = self._parse_expr('"a" & "b"')
        assert isinstance(expr, VbaBinaryExpression)
        self.assertEqual(expr.operator, '&')

    def test_comparison_eq(self):
        expr = self._parse_expr('a = b')
        assert isinstance(expr, VbaBinaryExpression)
        self.assertEqual(expr.operator, '=')

    def test_comparison_neq(self):
        expr = self._parse_expr('a <> b')
        assert isinstance(expr, VbaBinaryExpression)
        self.assertEqual(expr.operator, '<>')

    def test_comparison_lt(self):
        expr = self._parse_expr('a < b')
        assert isinstance(expr, VbaBinaryExpression)
        self.assertEqual(expr.operator, '<')

    def test_logical_and(self):
        expr = self._parse_expr('a And b')
        assert isinstance(expr, VbaBinaryExpression)
        self.assertEqual(expr.operator, 'And')

    def test_logical_or(self):
        expr = self._parse_expr('a Or b')
        assert isinstance(expr, VbaBinaryExpression)
        self.assertEqual(expr.operator, 'Or')

    def test_logical_not(self):
        expr = self._parse_expr('Not a')
        assert isinstance(expr, VbaUnaryExpression)
        self.assertEqual(expr.operator, 'Not')

    def test_logical_xor(self):
        expr = self._parse_expr('a Xor b')
        assert isinstance(expr, VbaBinaryExpression)
        self.assertEqual(expr.operator, 'Xor')

    def test_unary_minus(self):
        expr = self._parse_expr('-5')
        assert isinstance(expr, VbaUnaryExpression)
        self.assertEqual(expr.operator, '-')

    def test_parenthesized(self):
        expr = self._parse_expr('(1 + 2)')
        assert isinstance(expr, VbaParenExpression)

    def test_function_call(self):
        expr = self._parse_expr('Len("hello")')
        assert isinstance(expr, VbaCallExpression)
        assert isinstance(expr.callee, VbaIdentifier)
        self.assertEqual(expr.callee.name, 'Len')
        self.assertEqual(len(expr.arguments), 1)

    def test_member_access(self):
        expr = self._parse_expr('obj.Name')
        assert isinstance(expr, VbaMemberAccess)
        self.assertEqual(expr.member, 'Name')

    def test_new_expression(self):
        code = 'Set x = New Collection'
        ast = VbaParser(code).parse()
        from refinery.lib.scripts.vba.model import VbaSetStatement
        stmt = ast.body[0]
        assert isinstance(stmt.value, VbaNewExpression)

    def test_typeof_is(self):
        expr = self._parse_expr('TypeOf obj Is Collection')
        assert isinstance(expr, VbaTypeOfIsExpression)

    def test_precedence_multiply_before_add(self):
        expr = self._parse_expr('1 + 2 * 3')
        assert isinstance(expr, VbaBinaryExpression)
        self.assertEqual(expr.operator, '+')
        assert isinstance(expr.right, VbaBinaryExpression)
        self.assertEqual(expr.right.operator, '*')

    def test_precedence_and_before_or(self):
        expr = self._parse_expr('a Or b And c')
        assert isinstance(expr, VbaBinaryExpression)
        self.assertEqual(expr.operator, 'Or')
        assert isinstance(expr.right, VbaBinaryExpression)
        self.assertEqual(expr.right.operator, 'And')

    def test_chained_member_access(self):
        expr = self._parse_expr('a.b.c')
        assert isinstance(expr, VbaMemberAccess)
        self.assertEqual(expr.member, 'c')
        assert isinstance(expr.object, VbaMemberAccess)
        self.assertEqual(expr.object.member, 'b')

    def test_function_call_multiple_args(self):
        expr = self._parse_expr('Mid("Hello", 2, 3)')
        assert isinstance(expr, VbaCallExpression)
        self.assertEqual(len(expr.arguments), 3)

    def test_exponentiation_left_associative(self):
        expr = self._parse_expr('2 ^ 3 ^ 4')
        assert isinstance(expr, VbaBinaryExpression)
        self.assertEqual(expr.operator, '^')
        assert isinstance(expr.left, VbaBinaryExpression)
        self.assertEqual(expr.left.operator, '^')

    def test_exponentiation_binds_tighter_than_unary_negation(self):
        expr = self._parse_expr('-2 ^ 2')
        assert isinstance(expr, VbaUnaryExpression)
        self.assertEqual(expr.operator, '-')
        assert isinstance(expr.operand, VbaBinaryExpression)
        self.assertEqual(expr.operand.operator, '^')
        assert isinstance(expr.operand.left, VbaIntegerLiteral)
        self.assertEqual(expr.operand.left.value, 2)
        assert isinstance(expr.operand.right, VbaIntegerLiteral)
        self.assertEqual(expr.operand.right.value, 2)

    def test_exponentiation_with_negative_exponent(self):
        code = 'Sub T()\ny = x ^ -2\nEnd Sub'
        ast = VbaParser(code).parse()
        sub = ast.body[0]
        stmt = sub.body[0]
        assert isinstance(stmt, VbaLetStatement)
        expr = stmt.value
        assert isinstance(expr, VbaBinaryExpression)
        self.assertEqual(expr.operator, '^')
        assert isinstance(expr.right, VbaUnaryExpression)
        self.assertEqual(expr.right.operator, '-')
        assert isinstance(expr.right.operand, VbaIntegerLiteral)
        self.assertEqual(expr.right.operand.value, 2)

    def test_exponentiation_with_positive_exponent(self):
        code = 'Sub T()\ny = x ^ +2\nEnd Sub'
        ast = VbaParser(code).parse()
        sub = ast.body[0]
        stmt = sub.body[0]
        assert isinstance(stmt, VbaLetStatement)
        expr = stmt.value
        assert isinstance(expr, VbaBinaryExpression)
        self.assertEqual(expr.operator, '^')
        assert isinstance(expr.right, VbaIntegerLiteral)
        self.assertEqual(expr.right.value, 2)

    def test_line_continuation_with_trailing_whitespace(self):
        expr = self._parse_expr('1 + _  \n  2')
        assert isinstance(expr, VbaBinaryExpression)
        self.assertEqual(expr.operator, '+')
        assert isinstance(expr.left, VbaIntegerLiteral)
        self.assertEqual(expr.left.value, 1)
        assert isinstance(expr.right, VbaIntegerLiteral)
        self.assertEqual(expr.right.value, 2)
