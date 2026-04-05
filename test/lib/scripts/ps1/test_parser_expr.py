from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.ps1.parser import Ps1Parser
from refinery.lib.scripts.ps1.model import (
    Ps1AccessKind,
    Ps1ArrayLiteral,
    Ps1AssignmentExpression,
    Ps1BinaryExpression,
    Ps1CastExpression,
    Ps1ScopeModifier,
    Ps1ExpandableString,
    Ps1HashLiteral,
    Ps1HereString,
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

    def test_variable_drive_qualified(self):
        expr = self._parse_expr('$HKLM:Software')
        self.assertIsInstance(expr, Ps1Variable)
        self.assertEqual(expr.scope, Ps1ScopeModifier.DRIVE)
        self.assertEqual(expr.name, 'Software')

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

    def test_unary_csplit(self):
        expr = self._parse_expr('-csplit "hello world"')
        self.assertIsInstance(expr, Ps1UnaryExpression)
        self.assertEqual(expr.operator, '-csplit')
        self.assertTrue(expr.prefix)

    def test_unary_isplit(self):
        expr = self._parse_expr('-isplit "hello world"')
        self.assertIsInstance(expr, Ps1UnaryExpression)
        self.assertEqual(expr.operator, '-isplit')
        self.assertTrue(expr.prefix)

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

    def test_hash_literal_paren_key(self):
        expr = self._parse_expr('@{ (1+2) = "three" }')
        self.assertIsInstance(expr, Ps1HashLiteral)
        self.assertEqual(len(expr.pairs), 1)
        self.assertIsInstance(expr.pairs[0][0], Ps1ParenExpression)

    def test_hash_literal_negative_integer_key(self):
        expr = self._parse_expr('@{ -1 = "neg" }')
        self.assertIsInstance(expr, Ps1HashLiteral)
        self.assertEqual(len(expr.pairs), 1)
        self.assertIsInstance(expr.pairs[0][0], Ps1UnaryExpression)

    def test_hash_literal_real_key(self):
        expr = self._parse_expr('@{ 3.14 = "pi" }')
        self.assertIsInstance(expr, Ps1HashLiteral)
        self.assertEqual(len(expr.pairs), 1)
        self.assertIsInstance(expr.pairs[0][0], Ps1RealLiteral)

    def test_hash_literal_subexpression_key(self):
        expr = self._parse_expr('@{ $("key") = "val" }')
        self.assertIsInstance(expr, Ps1HashLiteral)
        self.assertEqual(len(expr.pairs), 1)
        self.assertIsInstance(expr.pairs[0][0], Ps1SubExpression)

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

    def test_unary_comma_disabled_in_method_args(self):
        expr = self._parse_expr('$obj.Method($a, $b)')
        self.assertIsInstance(expr, Ps1InvokeMember)
        self.assertEqual(len(expr.arguments), 2)
        self.assertIsInstance(expr.arguments[0], Ps1Variable)
        self.assertIsInstance(expr.arguments[1], Ps1Variable)

    def test_unary_comma_not_parsed_in_method_args(self):
        # In the reference parser (Parser.cs:7094-7097), when _disableCommaOperator is set,
        # UnaryExpressionRule returns null for a leading comma.  In a method argument context
        # this means the comma should not be parsed as a unary array-wrap operator.  Instead,
        # the expression parser should return None, leaving the comma unconsumed.
        p = Ps1Parser('$obj.Method(,$a)')
        script = p.parse()
        self.assertIsInstance(script, Ps1Script)
        stmt = script.body[0]
        self.assertIsInstance(stmt, Ps1ExpressionStatement)
        expr = stmt.expression
        self.assertIsInstance(expr, Ps1InvokeMember)
        # With the comma disabled the parser must not consume the leading comma as a unary
        # operator.  The first call to ExpressionRule returns None, so the arguments list should
        # be empty or the comma should be left as an error rather than silently wrapping $a in
        # an array.
        for arg in expr.arguments:
            self.assertNotIsInstance(arg, Ps1ArrayLiteral)

    def test_hex_literal_with_multiplier_suffix(self):
        expr = self._parse_expr('0x10kb')
        self.assertIsInstance(expr, Ps1RealLiteral)
        self.assertAlmostEqual(expr.value, 16 * 1024)

    def test_binary_literal_with_multiplier_suffix(self):
        expr = self._parse_expr('0b1010mb')
        self.assertIsInstance(expr, Ps1RealLiteral)
        self.assertAlmostEqual(expr.value, 10 * 1024 ** 2)

    def test_hex_literal_with_gb_suffix(self):
        expr = self._parse_expr('0xFFgb')
        self.assertIsInstance(expr, Ps1RealLiteral)
        self.assertAlmostEqual(expr.value, 255 * 1024 ** 3)

    def test_type_literal_followed_by_comma_is_not_cast(self):
        # [int],1 should be an array of a type expression and an integer, not a cast.
        expr = self._parse_expr('[int], 1')
        self.assertIsInstance(expr, Ps1ArrayLiteral)
        self.assertEqual(len(expr.elements), 2)
        self.assertIsInstance(expr.elements[0], Ps1TypeExpression)
        self.assertEqual(expr.elements[0].name, 'int')
        self.assertIsInstance(expr.elements[1], Ps1IntegerLiteral)
        self.assertEqual(expr.elements[1].value, 1)

    def test_integer_with_long_suffix_and_multiplier(self):
        expr = self._parse_expr('10lkb')
        self.assertIsInstance(expr, Ps1RealLiteral)
        self.assertAlmostEqual(expr.value, 10 * 1024)

    def test_hex_integer_with_long_suffix_and_multiplier(self):
        expr = self._parse_expr('0xAlgb')
        self.assertIsInstance(expr, Ps1RealLiteral)
        self.assertAlmostEqual(expr.value, 10 * 1024 ** 3)

    def test_expandable_string_nested_dq_in_subexpr(self):
        expr = self._parse_expr('"value: $($x.ToString("N2"))"')
        self.assertIsInstance(expr, Ps1ExpandableString)
        has_subexpr = any(isinstance(p, Ps1SubExpression) for p in expr.parts)
        self.assertTrue(has_subexpr)

    def test_expandable_string_special_var_dollar_stops(self):
        expr = self._parse_expr('"$$x"')
        self.assertIsInstance(expr, Ps1ExpandableString)
        has_var = any(isinstance(p, Ps1Variable) and p.name == '$' for p in expr.parts)
        self.assertTrue(has_var, 'should contain variable $$ (name=$)')
        has_literal_x = any(
            isinstance(p, Ps1StringLiteral) and 'x' in p.value for p in expr.parts)
        self.assertTrue(has_literal_x, 'should contain literal x after $$')

    def test_digit_variable_standalone(self):
        for src, expected_name in [('$0', '0'), ('$1', '1'), ('$1foo', '1foo')]:
            with self.subTest(src=src):
                expr = self._parse_expr(src)
                self.assertIsInstance(expr, Ps1Variable)
                self.assertEqual(expr.name, expected_name)

    def test_digit_variable_in_expandable_string(self):
        expr = self._parse_expr('"text $1 end"')
        self.assertIsInstance(expr, Ps1ExpandableString)
        has_var = any(isinstance(p, Ps1Variable) and p.name == '1' for p in expr.parts)
        self.assertTrue(has_var, 'should contain variable $1 (name=1)')

    def test_expandable_string_special_var_question_stops(self):
        expr = self._parse_expr('"$?x"')
        self.assertIsInstance(expr, Ps1ExpandableString)
        has_var = any(isinstance(p, Ps1Variable) and p.name == '?' for p in expr.parts)
        self.assertTrue(has_var, 'should contain variable $? (name=?)')
        has_literal_x = any(
            isinstance(p, Ps1StringLiteral) and 'x' in p.value for p in expr.parts)
        self.assertTrue(has_literal_x, 'should contain literal x after $?')

    def test_here_string_verbatim_whitespace_after_header(self):
        # PowerShell allows whitespace (spaces/tabs) between the @' header and the newline.
        # The whitespace must not become part of the string content.
        expr = self._parse_expr("@'   \nline one\nline two\n'@")
        self.assertIsInstance(expr, Ps1HereString)
        self.assertEqual(expr.value, 'line one\nline two')

    def test_here_string_expandable_whitespace_after_header(self):
        expr = self._parse_expr('@"   \nline one\nline two\n"@')
        self.assertIsInstance(expr, Ps1HereString)
        self.assertEqual(expr.value, 'line one\nline two')

    def test_here_string_verbatim_tab_after_header(self):
        expr = self._parse_expr("@'\t\ntext\n'@")
        self.assertIsInstance(expr, Ps1HereString)
        self.assertEqual(expr.value, 'text')

    def test_here_string_verbatim_bare_cr_line_endings(self):
        expr = self._parse_expr("@'\rline one\rline two\r'@")
        self.assertIsInstance(expr, Ps1HereString)
        self.assertEqual(expr.value, 'line one\rline two')

    def test_here_string_expandable_bare_cr_line_endings(self):
        expr = self._parse_expr('@"\rline one\rline two\r"@')
        self.assertIsInstance(expr, Ps1HereString)
        self.assertEqual(expr.value, 'line one\rline two')

    def test_member_access_newline_after_dot(self):
        expr = self._parse_expr('$obj.\n    Length')
        self.assertIsInstance(expr, Ps1MemberAccess)
        self.assertEqual(expr.member, 'Length')

    def test_method_call_newline_after_dot(self):
        expr = self._parse_expr('$obj.\n    Method()')
        self.assertIsInstance(expr, Ps1InvokeMember)
        self.assertEqual(expr.member, 'Method')

    def test_static_access_newline_after_double_colon(self):
        expr = self._parse_expr('[int]::\n    MaxValue')
        self.assertIsInstance(expr, Ps1MemberAccess)
        self.assertEqual(expr.member, 'MaxValue')
        self.assertEqual(expr.access, Ps1AccessKind.STATIC)

    def test_cast_with_unary_not_operator(self):
        expr = self._parse_expr('[int]-not $false')
        self.assertIsInstance(expr, Ps1CastExpression)
        self.assertEqual(expr.type_name, 'int')
        self.assertIsInstance(expr.operand, Ps1UnaryExpression)
        self.assertEqual(expr.operand.operator, '-not')
        self.assertTrue(expr.operand.prefix)
        self.assertIsInstance(expr.operand.operand, Ps1Variable)
        self.assertEqual(expr.operand.operand.name, 'false')

    def test_chained_fluent_member_access(self):
        expr = self._parse_expr('$s.\n    Trim().\n    ToLower()')
        self.assertIsInstance(expr, Ps1InvokeMember)
        self.assertEqual(expr.member, 'ToLower')
        self.assertIsInstance(expr.object, Ps1InvokeMember)
        self.assertEqual(expr.object.member, 'Trim')
