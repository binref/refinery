from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.au3.model import (
    Au3ArrayAccess,
    Au3ArrayLiteral,
    Au3Assignment,
    Au3BinaryExpression,
    Au3BooleanLiteral,
    Au3Call,
    Au3DefaultLiteral,
    Au3ErrorNode,
    Au3ExpressionStatement,
    Au3FloatLiteral,
    Au3Identifier,
    Au3IntLiteral,
    Au3Macro,
    Au3MemberAccess,
    Au3NullLiteral,
    Au3ParenExpression,
    Au3StringLiteral,
    Au3Ternary,
    Au3UnaryExpression,
    Au3Variable,
    Au3WithMember,
)
from refinery.lib.scripts.au3.parser import Au3Parser


class TestAu3ParserExpr(TestBase):

    def _parse(self, source: str):
        script = Au3Parser(source).parse()
        self.assertEqual(script.errors, [])
        self.assertEqual(len(script.body), 1)
        return script.body[0]

    def _expr(self, code: str):
        stmt = self._parse(F'{code}\n')
        self.assertIsInstance(stmt, Au3ExpressionStatement)
        return stmt.expression

    def _binary(self, code: str) -> Au3BinaryExpression:
        expr = self._expr(code)
        self.assertIsInstance(expr, Au3BinaryExpression)
        return expr

    def test_integer_decimal(self):
        node = self._expr('42')
        self.assertIsInstance(node, Au3IntLiteral)
        self.assertEqual(node.value, 42)
        self.assertEqual(node.raw, '42')

    def test_integer_hex_sign_extension_32bit(self):
        node = self._expr('0x80000000')
        self.assertEqual(node.value, -2147483648)

    def test_integer_hex_sign_extension_64bit(self):
        node = self._expr('0x080000000')
        self.assertEqual(node.value, 2147483648)

    def test_integer_hex_plain(self):
        node = self._expr('0xFF')
        self.assertEqual(node.value, 255)

    def test_float(self):
        node = self._expr('3.5')
        self.assertIsInstance(node, Au3FloatLiteral)
        self.assertEqual(node.value, 3.5)

    def test_float_exponent(self):
        node = self._expr('1.5e3')
        self.assertEqual(node.value, 1500.0)

    def test_string_double_quotes(self):
        node = self._expr('"hi"')
        self.assertIsInstance(node, Au3StringLiteral)
        self.assertEqual(node.value, 'hi')
        self.assertEqual(node.raw, '"hi"')

    def test_string_single_quotes(self):
        node = self._expr("'hi'")
        self.assertEqual(node.value, 'hi')
        self.assertEqual(node.raw, "'hi'")

    def test_string_doubled_quote_escape(self):
        node = self._expr("'it''s'")
        self.assertEqual(node.value, "it's")

    def test_boolean_literals(self):
        node = self._expr('True')
        self.assertIsInstance(node, Au3BooleanLiteral)
        self.assertEqual(node.value, True)
        node = self._expr('false')
        self.assertIsInstance(node, Au3BooleanLiteral)
        self.assertEqual(node.value, False)

    def test_null_literal(self):
        self.assertIsInstance(self._expr('Null'), Au3NullLiteral)

    def test_default_literal(self):
        self.assertIsInstance(self._expr('Default'), Au3DefaultLiteral)

    def test_variable_name_case_folds(self):
        node = self._expr('$FOO')
        self.assertIsInstance(node, Au3Variable)
        self.assertEqual(node.name, 'foo')
        self.assertEqual(node.raw, '$FOO')

    def test_macro(self):
        node = self._expr('@SCRIPTDIR')
        self.assertIsInstance(node, Au3Macro)
        self.assertEqual(node.name, 'scriptdir')
        self.assertEqual(node.raw, '@SCRIPTDIR')

    def test_identifier_case_folds(self):
        node = self._expr('MsgBox')
        self.assertIsInstance(node, Au3Identifier)
        self.assertEqual(node.name, 'msgbox')
        self.assertEqual(node.raw, 'MsgBox')

    def test_unary_not(self):
        node = self._expr('Not $x')
        self.assertIsInstance(node, Au3UnaryExpression)
        self.assertEqual(node.operator, 'not')
        self.assertIsInstance(node.operand, Au3Variable)

    def test_unary_minus(self):
        node = self._expr('-1')
        self.assertIsInstance(node, Au3UnaryExpression)
        self.assertEqual(node.operator, '-')
        self.assertIsInstance(node.operand, Au3IntLiteral)

    def test_unary_stacked(self):
        node = self._expr('- -1')
        self.assertIsInstance(node, Au3UnaryExpression)
        self.assertIsInstance(node.operand, Au3UnaryExpression)

    def test_precedence_not_tighter_than_comparison(self):
        node = self._binary('Not 1 = 2')
        self.assertEqual(node.operator, '=')
        self.assertIsInstance(node.left, Au3UnaryExpression)
        self.assertIsInstance(node.right, Au3IntLiteral)

    def test_precedence_caret_tighter_than_mul(self):
        node = self._binary('2 ^ 2 * 3')
        self.assertEqual(node.operator, '*')
        self.assertEqual(node.left.operator, '^')

    def test_precedence_mul_tighter_than_plus(self):
        node = self._binary('1 + 2 * 3')
        self.assertEqual(node.operator, '+')
        self.assertEqual(node.right.operator, '*')

    def test_precedence_plus_tighter_than_concat(self):
        node = self._binary('"a" + 1 & "b"')
        self.assertEqual(node.operator, '&')
        self.assertEqual(node.left.operator, '+')

    def test_precedence_concat_tighter_than_comparison(self):
        node = self._binary('"a" & "b" = "ab"')
        self.assertEqual(node.operator, '=')
        self.assertEqual(node.left.operator, '&')

    def test_precedence_comparison_tighter_than_ternary(self):
        node = self._expr('$x ? 1 : 2 = 3')
        self.assertIsInstance(node, Au3Ternary)
        self.assertEqual(node.alternate.operator, '=')

    def test_precedence_ternary_tighter_than_and(self):
        node = self._binary('$x ? 1 : 2 And $y')
        self.assertEqual(node.operator, 'and')
        self.assertIsInstance(node.left, Au3Ternary)

    def test_and_or_share_one_tier_left_to_right(self):
        node = self._binary('True Or False And False')
        self.assertEqual(node.operator, 'and')
        self.assertEqual(node.left.operator, 'or')

    def test_left_associativity_caret(self):
        node = self._binary('2 ^ 2 ^ 3')
        self.assertEqual(node.left.operator, '^')
        self.assertEqual(node.left.left.value, 2)
        self.assertEqual(node.left.right.value, 2)
        self.assertEqual(node.right.value, 3)

    def test_left_associativity_minus(self):
        node = self._binary('10 - 3 - 2')
        self.assertEqual(node.left.operator, '-')
        self.assertEqual(node.left.left.value, 10)
        self.assertEqual(node.right.value, 2)

    def test_left_associativity_mixed_same_tier(self):
        node = self._binary('1 + 2 - 3')
        self.assertEqual(node.operator, '-')
        self.assertEqual(node.left.operator, '+')

    def test_paren_expression(self):
        node = self._binary('(1 + 2) * 3')
        self.assertEqual(node.operator, '*')
        self.assertIsInstance(node.left, Au3ParenExpression)
        self.assertEqual(node.left.expression.operator, '+')

    def test_ternary(self):
        node = self._expr('$a ? $b : $c')
        self.assertIsInstance(node, Au3Ternary)
        self.assertIsInstance(node.condition, Au3Variable)
        self.assertEqual(node.consequent.name, 'b')
        self.assertEqual(node.alternate.name, 'c')

    def test_ternary_chain_is_right_associative(self):
        node = self._expr('$a ? $b : $c ? $d : $e')
        self.assertIsInstance(node, Au3Ternary)
        self.assertEqual(node.consequent.name, 'b')
        self.assertIsInstance(node.alternate, Au3Ternary)
        self.assertEqual(node.alternate.condition.name, 'c')

    def test_ternary_nested_in_consequent(self):
        node = self._expr('$a ? $b ? $c : $d : $e')
        self.assertIsInstance(node.consequent, Au3Ternary)
        self.assertEqual(node.consequent.condition.name, 'b')

    def test_call(self):
        node = self._expr('f(1, "two")')
        self.assertIsInstance(node, Au3Call)
        self.assertIsInstance(node.callee, Au3Identifier)
        self.assertEqual(node.callee.name, 'f')
        self.assertEqual(len(node.arguments), 2)
        self.assertEqual(node.arguments[1].value, 'two')

    def test_call_no_arguments(self):
        node = self._expr('f()')
        self.assertIsInstance(node, Au3Call)
        self.assertEqual(node.arguments, [])

    def test_chained_calls(self):
        node = self._expr('f(1)(2)')
        self.assertIsInstance(node, Au3Call)
        self.assertIsInstance(node.callee, Au3Call)
        self.assertEqual(node.callee.arguments[0].value, 1)

    def test_member_access(self):
        node = self._expr('$obj.prop')
        self.assertIsInstance(node, Au3MemberAccess)
        self.assertEqual(node.member, 'prop')
        self.assertEqual(node.raw, 'prop')
        self.assertIsInstance(node.object, Au3Variable)

    def test_member_name_may_be_keyword(self):
        node = self._expr('$obj.step')
        self.assertIsInstance(node, Au3MemberAccess)
        self.assertEqual(node.member, 'step')

    def test_member_access_chain(self):
        node = self._expr('$a.b.c')
        self.assertIsInstance(node, Au3MemberAccess)
        self.assertEqual(node.member, 'c')
        self.assertIsInstance(node.object, Au3MemberAccess)
        self.assertEqual(node.object.member, 'b')

    def test_array_access(self):
        node = self._expr('$a[0]')
        self.assertIsInstance(node, Au3ArrayAccess)
        self.assertEqual(node.index.value, 0)
        self.assertIsInstance(node.array, Au3Variable)

    def test_array_access_chain(self):
        node = self._expr('$a[0][1]')
        self.assertIsInstance(node, Au3ArrayAccess)
        self.assertEqual(node.index.value, 1)
        self.assertIsInstance(node.array, Au3ArrayAccess)

    def test_postfix_mix(self):
        node = self._expr('$obj.method(1).prop[$i]')
        self.assertIsInstance(node, Au3ArrayAccess)
        self.assertIsInstance(node.array, Au3MemberAccess)
        self.assertIsInstance(node.array.object, Au3Call)
        self.assertIsInstance(node.array.object.callee, Au3MemberAccess)

    def test_array_literal(self):
        node = self._expr('[1, "two", 3]')
        self.assertIsInstance(node, Au3ArrayLiteral)
        self.assertEqual(len(node.elements), 3)
        self.assertEqual(node.elements[1].value, 'two')

    def test_array_literal_nested(self):
        node = self._expr('[[1], [2]]')
        self.assertIsInstance(node.elements[0], Au3ArrayLiteral)
        self.assertEqual(node.elements[0].elements[0].value, 1)

    def test_assignment(self):
        node = self._expr('$x = 1')
        self.assertIsInstance(node, Au3Assignment)
        self.assertEqual(node.operator, '=')
        self.assertEqual(node.target.name, 'x')
        self.assertEqual(node.value.value, 1)

    def test_assignment_rhs_is_comparison(self):
        node = self._expr('$x = $y = 1')
        self.assertIsInstance(node, Au3Assignment)
        self.assertEqual(node.value.operator, '=')
        self.assertEqual(node.value.left.name, 'y')

    def test_strict_equality_is_comparison_not_assignment(self):
        node = self._expr('$x == 1')
        self.assertIsInstance(node, Au3BinaryExpression)
        self.assertEqual(node.operator, '==')

    def test_compound_assignments(self):
        for code, operator in (
            ('$x += 1', '+='),
            ('$x -= 1', '-='),
            ('$x *= 1', '*='),
            ('$x /= 1', '/='),
            ('$x &= 1', '&='),
        ):
            node = self._expr(code)
            self.assertIsInstance(node, Au3Assignment)
            self.assertEqual(node.operator, operator)

    def test_assignment_to_array_element(self):
        node = self._expr('$a[0] = 1')
        self.assertIsInstance(node, Au3Assignment)
        self.assertIsInstance(node.target, Au3ArrayAccess)

    def test_assignment_to_object_member(self):
        node = self._expr('$obj.prop = 1')
        self.assertIsInstance(node, Au3Assignment)
        self.assertIsInstance(node.target, Au3MemberAccess)

    def test_call_result_is_not_lvalue(self):
        node = self._expr('f() = 1')
        self.assertIsInstance(node, Au3BinaryExpression)
        self.assertEqual(node.operator, '=')
        self.assertIsInstance(node.left, Au3Call)

    def test_with_member_assignment_inside_with(self):
        stmt = self._parse('With $x\n.prop = 1\nEndWith\n')
        self.assertIsInstance(stmt.body[0], Au3ExpressionStatement)
        assignment = stmt.body[0].expression
        self.assertIsInstance(assignment, Au3Assignment)
        self.assertIsInstance(assignment.target, Au3WithMember)
        self.assertEqual(assignment.target.member, 'prop')

    def test_with_member_rejected_outside_with(self):
        script = Au3Parser('.prop = 1\n').parse()
        self.assertNotEqual(script.errors, [])
        error = script.body[0]
        self.assertIsInstance(error, Au3ErrorNode)
        self.assertEqual(error.text, '.prop = 1')

    def test_line_continuation_in_expression(self):
        node = self._expr('$x = 1 + _\n    2')
        self.assertIsInstance(node, Au3Assignment)
        self.assertEqual(node.value.operator, '+')
        self.assertEqual(node.value.right.value, 2)
