from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.ps1.parser import Ps1Parser
from refinery.lib.scripts.ps1.model import (
    Ps1ArrayLiteral,
    Ps1AssignmentExpression,
    Ps1BinaryExpression,
    Ps1CastExpression,
    Ps1ExpandableString,
    Ps1HashLiteral,
    Ps1IndexExpression,
    Ps1IntegerLiteral,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1ParenExpression,
    Ps1RangeExpression,
    Ps1RealLiteral,
    Ps1ScriptBlock,
    Ps1StringLiteral,
    Ps1SubExpression,
    Ps1TypeExpression,
    Ps1UnaryExpression,
    Ps1Variable,
    Ps1ExpressionStatement,
    Ps1Script,
    Ps1ArrayExpression,
)


class TestPs1ParserExpressions(TestBase):

    def _parse_expr(self, source: str):
        p = Ps1Parser(source)
        script = p.parse()
        self.assertIsInstance(script, Ps1Script)
        self.assertTrue(len(script.body) > 0)
        stmt = script.body[0]
        self.assertIsInstance(stmt, Ps1ExpressionStatement)
        return stmt.expression

    def test_integer_literal(self):
        expr = self._parse_expr('42')
        self.assertIsInstance(expr, Ps1IntegerLiteral)
        self.assertEqual(expr.value, 42)

    def test_hex_literal(self):
        expr = self._parse_expr('0xDEAD')
        self.assertIsInstance(expr, Ps1IntegerLiteral)
        self.assertEqual(expr.value, 0xDEAD)

    def test_real_literal(self):
        expr = self._parse_expr('3.14')
        self.assertIsInstance(expr, Ps1RealLiteral)
        self.assertAlmostEqual(expr.value, 3.14)

    def test_string_literal_verbatim(self):
        expr = self._parse_expr("'hello'")
        self.assertIsInstance(expr, Ps1StringLiteral)
        self.assertEqual(expr.value, 'hello')

    def test_string_literal_expandable_no_vars(self):
        expr = self._parse_expr('"hello"')
        self.assertIsInstance(expr, Ps1StringLiteral)
        self.assertEqual(expr.value, 'hello')

    def test_expandable_string_with_variable(self):
        expr = self._parse_expr('"hello $name"')
        self.assertIsInstance(expr, Ps1ExpandableString)
        self.assertTrue(len(expr.parts) >= 2)

    def test_expandable_string_with_subexpression(self):
        expr = self._parse_expr('"result: $(1+2)"')
        self.assertIsInstance(expr, Ps1ExpandableString)
        has_subexpr = any(isinstance(p, Ps1SubExpression) for p in expr.parts)
        self.assertTrue(has_subexpr)

    def test_variable(self):
        expr = self._parse_expr('$x')
        self.assertIsInstance(expr, Ps1Variable)
        self.assertEqual(expr.name, 'x')

    def test_variable_scoped(self):
        expr = self._parse_expr('$env:PATH')
        self.assertIsInstance(expr, Ps1Variable)
        self.assertEqual(expr.name, 'PATH')

    def test_addition(self):
        expr = self._parse_expr('1 + 2')
        self.assertIsInstance(expr, Ps1BinaryExpression)
        self.assertEqual(expr.operator, '+')
        self.assertIsInstance(expr.left, Ps1IntegerLiteral)
        self.assertIsInstance(expr.right, Ps1IntegerLiteral)

    def test_precedence_mul_over_add(self):
        expr = self._parse_expr('1 + 2 * 3')
        self.assertIsInstance(expr, Ps1BinaryExpression)
        self.assertEqual(expr.operator, '+')
        self.assertIsInstance(expr.right, Ps1BinaryExpression)
        self.assertEqual(expr.right.operator, '*')

    def test_comparison(self):
        expr = self._parse_expr('$x -eq 1')
        self.assertIsInstance(expr, Ps1BinaryExpression)
        self.assertEqual(expr.operator, '-eq')

    def test_logical_operators(self):
        expr = self._parse_expr('$a -and $b -or $c')
        self.assertIsInstance(expr, Ps1BinaryExpression)
        self.assertEqual(expr.operator, '-or')
        self.assertIsInstance(expr.left, Ps1BinaryExpression)
        self.assertEqual(expr.left.operator, '-and')

    def test_bitwise_operators(self):
        expr = self._parse_expr('$a -band 0xFF')
        self.assertIsInstance(expr, Ps1BinaryExpression)
        self.assertEqual(expr.operator, '-band')

    def test_range_expression(self):
        expr = self._parse_expr('1..10')
        self.assertIsInstance(expr, Ps1RangeExpression)
        self.assertIsInstance(expr.start, Ps1IntegerLiteral)
        self.assertIsInstance(expr.end, Ps1IntegerLiteral)

    def test_array_literal(self):
        expr = self._parse_expr('1, 2, 3')
        self.assertIsInstance(expr, Ps1ArrayLiteral)
        self.assertEqual(len(expr.elements), 3)

    def test_unary_not(self):
        expr = self._parse_expr('-not $x')
        self.assertIsInstance(expr, Ps1UnaryExpression)
        self.assertEqual(expr.operator, '-not')
        self.assertTrue(expr.prefix)

    def test_unary_negation(self):
        expr = self._parse_expr('-5')
        self.assertIsInstance(expr, Ps1UnaryExpression)
        self.assertEqual(expr.operator, '-')

    def test_unary_exclaim(self):
        expr = self._parse_expr('!$x')
        self.assertIsInstance(expr, Ps1UnaryExpression)
        self.assertEqual(expr.operator, '!')

    def test_prefix_increment(self):
        expr = self._parse_expr('++$x')
        self.assertIsInstance(expr, Ps1UnaryExpression)
        self.assertEqual(expr.operator, '++')
        self.assertTrue(expr.prefix)

    def test_postfix_increment(self):
        expr = self._parse_expr('$x++')
        self.assertIsInstance(expr, Ps1UnaryExpression)
        self.assertEqual(expr.operator, '++')
        self.assertFalse(expr.prefix)

    def test_cast_expression(self):
        expr = self._parse_expr('[int]$x')
        self.assertIsInstance(expr, Ps1CastExpression)
        self.assertEqual(expr.type_name, 'int')

    def test_type_expression(self):
        expr = self._parse_expr('[string]')
        self.assertIsInstance(expr, Ps1TypeExpression)
        self.assertEqual(expr.name, 'string')

    def test_member_access(self):
        expr = self._parse_expr('$s.Length')
        self.assertIsInstance(expr, Ps1MemberAccess)
        self.assertEqual(expr.member, 'Length')

    def test_static_member_access(self):
        expr = self._parse_expr('[int]::MaxValue')
        self.assertIsInstance(expr, Ps1MemberAccess)
        self.assertEqual(expr.member, 'MaxValue')

    def test_method_invocation(self):
        expr = self._parse_expr('$s.Substring(0, 5)')
        self.assertIsInstance(expr, Ps1InvokeMember)
        self.assertEqual(expr.member, 'Substring')
        self.assertEqual(len(expr.arguments), 2)

    def test_static_method_invocation(self):
        expr = self._parse_expr('[System.Text.Encoding]::UTF8.GetBytes("test")')
        self.assertIsInstance(expr, Ps1InvokeMember)

    def test_index_expression(self):
        expr = self._parse_expr('$arr[0]')
        self.assertIsInstance(expr, Ps1IndexExpression)
        self.assertIsInstance(expr.index, Ps1IntegerLiteral)

    def test_paren_expression(self):
        expr = self._parse_expr('(1 + 2)')
        self.assertIsInstance(expr, Ps1ParenExpression)

    def test_sub_expression(self):
        expr = self._parse_expr('$($x + $y)')
        self.assertIsInstance(expr, Ps1SubExpression)

    def test_array_expression(self):
        expr = self._parse_expr('@(1, 2, 3)')
        self.assertIsInstance(expr, Ps1ArrayExpression)

    def test_hash_literal(self):
        expr = self._parse_expr('@{ a = 1; b = 2 }')
        self.assertIsInstance(expr, Ps1HashLiteral)
        self.assertEqual(len(expr.pairs), 2)

    def test_script_block(self):
        expr = self._parse_expr('{ $x + 1 }')
        self.assertIsInstance(expr, Ps1ScriptBlock)

    def test_assignment(self):
        expr = self._parse_expr('$x = 42')
        self.assertIsInstance(expr, Ps1AssignmentExpression)
        self.assertEqual(expr.operator, '=')

    def test_compound_assignment(self):
        expr = self._parse_expr('$x += 1')
        self.assertIsInstance(expr, Ps1AssignmentExpression)
        self.assertEqual(expr.operator, '+=')

    def test_format_operator(self):
        expr = self._parse_expr('"hello {0}" -f "world"')
        self.assertIsInstance(expr, Ps1BinaryExpression)
        self.assertEqual(expr.operator, '-f')

    def test_chained_member_access(self):
        expr = self._parse_expr('$s.Trim().ToLower()')
        self.assertIsInstance(expr, Ps1InvokeMember)
        self.assertEqual(expr.member, 'ToLower')
        self.assertIsInstance(expr.object, Ps1InvokeMember)

    def test_nested_index(self):
        expr = self._parse_expr('$a[0][1]')
        self.assertIsInstance(expr, Ps1IndexExpression)
        self.assertIsInstance(expr.object, Ps1IndexExpression)

    def test_unary_prefix_operators_allow_newline_before_operand(self):
        cases = {
            '-' : (' -\n    $y', '-'),
            '+' : (' +\n    $y', '+'),
            '!' : (' !\n    $y', '!'),
            '++': ('++\n    $y', '++'),
            '--': ('--\n    $y', '--'),
        }
        for label, (src, op) in cases.items():
            with self.subTest(operator=label):
                expr = self._parse_expr(src)
                self.assertIsInstance(expr, Ps1UnaryExpression)
                self.assertEqual(expr.operator, op)
                self.assertTrue(expr.prefix)
                self.assertIsInstance(expr.operand, Ps1Variable)
                self.assertEqual(expr.operand.name, 'y')

    def test_expandable_string_nested_dq_in_subexpr(self):
        expr = self._parse_expr('"value: $($x.ToString("N2"))"')
        self.assertIsInstance(expr, Ps1ExpandableString)
        has_subexpr = any(isinstance(p, Ps1SubExpression) for p in expr.parts)
        self.assertTrue(has_subexpr)
