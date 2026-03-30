from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsBigIntLiteral,
    JsBinaryExpression,
    JsBooleanLiteral,
    JsCallExpression,
    JsConditionalExpression,
    JsExpressionStatement,
    JsFunctionExpression,
    JsIdentifier,
    JsLogicalExpression,
    JsMemberExpression,
    JsNewExpression,
    JsNullLiteral,
    JsNumericLiteral,
    JsObjectExpression,
    JsParenthesizedExpression,
    JsProperty,
    JsRegExpLiteral,
    JsScript,
    JsSequenceExpression,
    JsSpreadElement,
    JsStringLiteral,
    JsTemplateLiteral,
    JsThisExpression,
    JsUnaryExpression,
    JsUpdateExpression,
    JsYieldExpression,
)


class TestJsParserExpressions(TestBase):

    def _parse_expr(self, source: str):
        p = JsParser(source)
        script = p.parse()
        self.assertIsInstance(script, JsScript)
        self.assertTrue(len(script.body) > 0)
        stmt = script.body[0]
        self.assertIsInstance(stmt, JsExpressionStatement)
        return stmt.expression

    def test_integer_literal(self):
        expr = self._parse_expr('42')
        self.assertIsInstance(expr, JsNumericLiteral)
        self.assertEqual(expr.value, 42)

    def test_hex_literal(self):
        expr = self._parse_expr('0xDEAD')
        self.assertIsInstance(expr, JsNumericLiteral)
        self.assertEqual(expr.value, 0xDEAD)

    def test_octal_literal(self):
        expr = self._parse_expr('0o17')
        self.assertIsInstance(expr, JsNumericLiteral)
        self.assertEqual(expr.value, 0o17)

    def test_binary_literal(self):
        expr = self._parse_expr('0b1010')
        self.assertIsInstance(expr, JsNumericLiteral)
        self.assertEqual(expr.value, 10)

    def test_float_literal(self):
        expr = self._parse_expr('3.14')
        self.assertIsInstance(expr, JsNumericLiteral)
        self.assertAlmostEqual(expr.value, 3.14)

    def test_bigint_literal(self):
        expr = self._parse_expr('100n')
        self.assertIsInstance(expr, JsBigIntLiteral)
        self.assertEqual(expr.value, 100)

    def test_string_single(self):
        expr = self._parse_expr("'hello'")
        self.assertIsInstance(expr, JsStringLiteral)
        self.assertEqual(expr.value, 'hello')

    def test_string_double(self):
        expr = self._parse_expr('"world"')
        self.assertIsInstance(expr, JsStringLiteral)
        self.assertEqual(expr.value, 'world')

    def test_regexp(self):
        expr = self._parse_expr('/abc/gi')
        self.assertIsInstance(expr, JsRegExpLiteral)
        self.assertEqual(expr.pattern, 'abc')
        self.assertEqual(expr.flags, 'gi')

    def test_boolean_true(self):
        expr = self._parse_expr('true')
        self.assertIsInstance(expr, JsBooleanLiteral)
        self.assertTrue(expr.value)

    def test_boolean_false(self):
        expr = self._parse_expr('false')
        self.assertIsInstance(expr, JsBooleanLiteral)
        self.assertFalse(expr.value)

    def test_null(self):
        expr = self._parse_expr('null')
        self.assertIsInstance(expr, JsNullLiteral)

    def test_this(self):
        expr = self._parse_expr('this')
        self.assertIsInstance(expr, JsThisExpression)

    def test_identifier(self):
        expr = self._parse_expr('foo')
        self.assertIsInstance(expr, JsIdentifier)
        self.assertEqual(expr.name, 'foo')

    def test_addition(self):
        expr = self._parse_expr('a + b')
        self.assertIsInstance(expr, JsBinaryExpression)
        self.assertEqual(expr.operator, '+')
        self.assertIsInstance(expr.left, JsIdentifier)
        self.assertIsInstance(expr.right, JsIdentifier)

    def test_precedence_mul_over_add(self):
        expr = self._parse_expr('a + b * c')
        self.assertIsInstance(expr, JsBinaryExpression)
        self.assertEqual(expr.operator, '+')
        self.assertIsInstance(expr.right, JsBinaryExpression)
        self.assertEqual(expr.right.operator, '*')

    def test_precedence_and_over_or(self):
        expr = self._parse_expr('a || b && c')
        self.assertIsInstance(expr, JsLogicalExpression)
        self.assertEqual(expr.operator, '||')
        self.assertIsInstance(expr.right, JsLogicalExpression)
        self.assertEqual(expr.right.operator, '&&')

    def test_exponentiation_right_assoc(self):
        expr = self._parse_expr('2 ** 3 ** 4')
        self.assertIsInstance(expr, JsBinaryExpression)
        self.assertEqual(expr.operator, '**')
        self.assertIsInstance(expr.right, JsBinaryExpression)
        self.assertEqual(expr.right.operator, '**')

    def test_comparison(self):
        expr = self._parse_expr('a === b')
        self.assertIsInstance(expr, JsBinaryExpression)
        self.assertEqual(expr.operator, '===')

    def test_ternary(self):
        expr = self._parse_expr('a ? b : c')
        self.assertIsInstance(expr, JsConditionalExpression)
        self.assertIsInstance(expr.test, JsIdentifier)
        self.assertIsInstance(expr.consequent, JsIdentifier)
        self.assertIsInstance(expr.alternate, JsIdentifier)

    def test_assignment(self):
        expr = self._parse_expr('x = 5')
        self.assertIsInstance(expr, JsAssignmentExpression)
        self.assertEqual(expr.operator, '=')

    def test_assignment_compound(self):
        expr = self._parse_expr('x += 5')
        self.assertIsInstance(expr, JsAssignmentExpression)
        self.assertEqual(expr.operator, '+=')

    def test_unary_not(self):
        expr = self._parse_expr('!x')
        self.assertIsInstance(expr, JsUnaryExpression)
        self.assertEqual(expr.operator, '!')
        self.assertTrue(expr.prefix)

    def test_unary_typeof(self):
        expr = self._parse_expr('typeof x')
        self.assertIsInstance(expr, JsUnaryExpression)
        self.assertEqual(expr.operator, 'typeof')

    def test_unary_negative(self):
        expr = self._parse_expr('-x')
        self.assertIsInstance(expr, JsUnaryExpression)
        self.assertEqual(expr.operator, '-')

    def test_prefix_increment(self):
        expr = self._parse_expr('++x')
        self.assertIsInstance(expr, JsUpdateExpression)
        self.assertEqual(expr.operator, '++')
        self.assertTrue(expr.prefix)

    def test_postfix_increment(self):
        expr = self._parse_expr('x++')
        self.assertIsInstance(expr, JsUpdateExpression)
        self.assertEqual(expr.operator, '++')
        self.assertFalse(expr.prefix)

    def test_member_dot(self):
        expr = self._parse_expr('a.b')
        self.assertIsInstance(expr, JsMemberExpression)
        self.assertFalse(expr.computed)
        self.assertFalse(expr.optional)

    def test_member_bracket(self):
        expr = self._parse_expr('a[0]')
        self.assertIsInstance(expr, JsMemberExpression)
        self.assertTrue(expr.computed)

    def test_member_optional(self):
        expr = self._parse_expr('a?.b')
        self.assertIsInstance(expr, JsMemberExpression)
        self.assertTrue(expr.optional)

    def test_call(self):
        expr = self._parse_expr('f(x, y)')
        self.assertIsInstance(expr, JsCallExpression)
        self.assertEqual(len(expr.arguments), 2)

    def test_new_expression(self):
        expr = self._parse_expr('new Foo(a)')
        self.assertIsInstance(expr, JsNewExpression)
        self.assertIsInstance(expr.callee, JsIdentifier)
        self.assertEqual(len(expr.arguments), 1)

    def test_array_literal(self):
        expr = self._parse_expr('[1, 2, 3]')
        self.assertIsInstance(expr, JsArrayExpression)
        self.assertEqual(len(expr.elements), 3)

    def test_array_elision(self):
        expr = self._parse_expr('[1,,3]')
        self.assertIsInstance(expr, JsArrayExpression)
        self.assertEqual(len(expr.elements), 3)
        self.assertIsNone(expr.elements[1])

    def test_object_literal(self):
        expr = self._parse_expr('({a: 1, b: 2})')
        self.assertIsInstance(expr, JsParenthesizedExpression)
        obj = expr.expression
        self.assertIsInstance(obj, JsObjectExpression)
        self.assertEqual(len(obj.properties), 2)

    def test_object_shorthand(self):
        expr = self._parse_expr('({x})')
        self.assertIsInstance(expr, JsParenthesizedExpression)
        obj = expr.expression
        self.assertIsInstance(obj, JsObjectExpression)
        prop = obj.properties[0]
        self.assertIsInstance(prop, JsProperty)
        self.assertTrue(prop.shorthand)

    def test_spread(self):
        expr = self._parse_expr('[...a]')
        self.assertIsInstance(expr, JsArrayExpression)
        self.assertIsInstance(expr.elements[0], JsSpreadElement)

    def test_function_expression(self):
        expr = self._parse_expr('(function(x) { return x })')
        self.assertIsInstance(expr, JsParenthesizedExpression)
        self.assertIsInstance(expr.expression, JsFunctionExpression)

    def test_arrow_no_params(self):
        expr = self._parse_expr('() => 42')
        self.assertIsInstance(expr, JsArrowFunctionExpression)
        self.assertEqual(len(expr.params), 0)
        self.assertIsInstance(expr.body, JsNumericLiteral)

    def test_arrow_single_param(self):
        expr = self._parse_expr('x => x + 1')
        self.assertIsInstance(expr, JsArrowFunctionExpression)
        self.assertEqual(len(expr.params), 1)

    def test_arrow_multiple_params(self):
        expr = self._parse_expr('(a, b) => a + b')
        self.assertIsInstance(expr, JsArrowFunctionExpression)
        self.assertEqual(len(expr.params), 2)

    def test_arrow_block_body(self):
        expr = self._parse_expr('(x) => { return x }')
        self.assertIsInstance(expr, JsArrowFunctionExpression)

    def test_template_literal(self):
        expr = self._parse_expr('`hello ${name} world`')
        self.assertIsInstance(expr, JsTemplateLiteral)
        self.assertEqual(len(expr.quasis), 2)
        self.assertEqual(len(expr.expressions), 1)

    def test_yield(self):
        expr = self._parse_expr('yield x')
        self.assertIsInstance(expr, JsYieldExpression)
        self.assertFalse(expr.delegate)

    def test_yield_delegate(self):
        expr = self._parse_expr('yield* gen()')
        self.assertIsInstance(expr, JsYieldExpression)
        self.assertTrue(expr.delegate)

    def test_sequence(self):
        expr = self._parse_expr('a, b, c')
        self.assertIsInstance(expr, JsSequenceExpression)
        self.assertEqual(len(expr.expressions), 3)

    def test_logical_nullish(self):
        expr = self._parse_expr('a ?? b')
        self.assertIsInstance(expr, JsLogicalExpression)
        self.assertEqual(expr.operator, '??')

    def test_instanceof(self):
        expr = self._parse_expr('a instanceof b')
        self.assertIsInstance(expr, JsBinaryExpression)
        self.assertEqual(expr.operator, 'instanceof')

    def test_in_operator(self):
        expr = self._parse_expr('a in b')
        self.assertIsInstance(expr, JsBinaryExpression)
        self.assertEqual(expr.operator, 'in')

    def test_chained_member(self):
        expr = self._parse_expr('a.b.c')
        self.assertIsInstance(expr, JsMemberExpression)
        self.assertIsInstance(expr.object, JsMemberExpression)

    def test_call_chain(self):
        expr = self._parse_expr('a()()')
        self.assertIsInstance(expr, JsCallExpression)
        self.assertIsInstance(expr.callee, JsCallExpression)

    def test_computed_property(self):
        expr = self._parse_expr('({[x]: y})')
        self.assertIsInstance(expr, JsParenthesizedExpression)
        obj = expr.expression
        self.assertIsInstance(obj, JsObjectExpression)
        self.assertTrue(obj.properties[0].computed)
