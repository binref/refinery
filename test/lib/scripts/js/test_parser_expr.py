from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsAssignmentPattern,
    JsAwaitExpression,
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
    JsObjectPattern,
    JsParenthesizedExpression,
    JsProperty,
    JsPropertyKind,
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

    def test_new_member_expression(self):
        expr = self._parse_expr('new Foo.Bar()')
        self.assertIsInstance(expr, JsNewExpression)
        self.assertIsInstance(expr.callee, JsMemberExpression)
        self.assertIsInstance(expr.callee.object, JsIdentifier)
        self.assertEqual(expr.callee.object.name, 'Foo')
        self.assertIsInstance(expr.callee.property, JsIdentifier)
        self.assertEqual(expr.callee.property.name, 'Bar')

    def test_new_member_chain(self):
        expr = self._parse_expr('new A.B.C(x)')
        self.assertIsInstance(expr, JsNewExpression)
        self.assertIsInstance(expr.callee, JsMemberExpression)
        self.assertEqual(expr.callee.property.name, 'C')
        inner = expr.callee.object
        self.assertIsInstance(inner, JsMemberExpression)
        self.assertEqual(inner.object.name, 'A')
        self.assertEqual(inner.property.name, 'B')
        self.assertEqual(len(expr.arguments), 1)

    def test_new_computed_member(self):
        expr = self._parse_expr('new Foo[x]()')
        self.assertIsInstance(expr, JsNewExpression)
        self.assertIsInstance(expr.callee, JsMemberExpression)
        self.assertTrue(expr.callee.computed)
        self.assertEqual(expr.callee.object.name, 'Foo')

    def test_new_no_args_with_member(self):
        expr = self._parse_expr('new Foo.Bar')
        self.assertIsInstance(expr, JsNewExpression)
        self.assertIsInstance(expr.callee, JsMemberExpression)
        self.assertEqual(expr.callee.object.name, 'Foo')
        self.assertEqual(expr.callee.property.name, 'Bar')
        self.assertEqual(len(expr.arguments), 0)

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

    def test_object_assignment_pattern_shorthand_default(self):
        expr = self._parse_expr('({a = d} = o)')
        self.assertIsInstance(expr, JsParenthesizedExpression)
        assign = expr.expression
        self.assertIsInstance(assign, JsAssignmentExpression)
        pattern = assign.left
        self.assertIsInstance(pattern, JsObjectPattern)
        self.assertEqual(len(pattern.properties), 1)
        prop = pattern.properties[0]
        self.assertIsInstance(prop, JsProperty)
        self.assertTrue(prop.shorthand)
        self.assertIsInstance(prop.value, JsAssignmentPattern)
        self.assertEqual(prop.value.right.name, 'd')

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
        ast = JsParser('function* g(){ (yield x); }').parse()
        yields = [n for n in ast.walk() if isinstance(n, JsYieldExpression)]
        self.assertEqual(len(yields), 1)
        self.assertFalse(yields[0].delegate)

    def test_yield_delegate(self):
        ast = JsParser('function* g(){ (yield* gen()); }').parse()
        yields = [n for n in ast.walk() if isinstance(n, JsYieldExpression)]
        self.assertEqual(len(yields), 1)
        self.assertTrue(yields[0].delegate)

    def test_yield_is_identifier_outside_generator(self):
        ast = JsParser('function h(){ var yield = 1; return yield; }').parse()
        self.assertEqual([n for n in ast.walk() if isinstance(n, JsYieldExpression)], [])

    def test_await_is_operator_in_async_function(self):
        ast = JsParser('async function f(){ await x; }').parse()
        self.assertEqual(len([n for n in ast.walk() if isinstance(n, JsAwaitExpression)]), 1)

    def test_await_is_identifier_outside_async(self):
        ast = JsParser('var await = 1; f(await);').parse()
        self.assertEqual([n for n in ast.walk() if isinstance(n, JsAwaitExpression)], [])

    def test_await_is_operator_in_object_async_method(self):
        ast = JsParser('var o = { async f(){ return await x; } };').parse()
        self.assertEqual(len([n for n in ast.walk() if isinstance(n, JsAwaitExpression)]), 1)

    def test_yield_is_operator_in_object_generator_method(self):
        ast = JsParser('var o = { *g(){ yield x; } };').parse()
        self.assertEqual(len([n for n in ast.walk() if isinstance(n, JsYieldExpression)]), 1)

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

    def test_computed_getter(self):
        expr = self._parse_expr('({ get ["a"]() { return 1; } })')
        obj = expr.expression
        self.assertIsInstance(obj, JsObjectExpression)
        prop = obj.properties[0]
        self.assertIsInstance(prop, JsProperty)
        self.assertTrue(prop.computed)
        self.assertTrue(prop.method)
        self.assertEqual(prop.kind, JsPropertyKind.GET)
        self.assertIsInstance(prop.key, JsStringLiteral)
        self.assertEqual(prop.key.value, 'a')

    def test_computed_setter(self):
        expr = self._parse_expr('({ set ["a"](v) {} })')
        obj = expr.expression
        prop = obj.properties[0]
        self.assertTrue(prop.computed)
        self.assertEqual(prop.kind, JsPropertyKind.SET)
        self.assertIsInstance(prop.key, JsStringLiteral)
        self.assertEqual(prop.key.value, 'a')

    def test_computed_async_method(self):
        expr = self._parse_expr('({ async ["m"]() {} })')
        obj = expr.expression
        prop = obj.properties[0]
        self.assertTrue(prop.computed)
        self.assertIsInstance(prop.value, JsFunctionExpression)
        self.assertTrue(prop.value.is_async)
        self.assertIsInstance(prop.key, JsStringLiteral)
        self.assertEqual(prop.key.value, 'm')

    def test_method_named_get(self):
        expr = self._parse_expr('({ get(x) { return x; } })')
        obj = expr.expression
        self.assertIsInstance(obj, JsObjectExpression)
        prop = obj.properties[0]
        self.assertIsInstance(prop, JsProperty)
        self.assertTrue(prop.method)
        self.assertFalse(prop.shorthand)
        self.assertEqual(prop.kind, JsPropertyKind.INIT)
        self.assertIsInstance(prop.key, JsIdentifier)
        self.assertEqual(prop.key.name, 'get')
        self.assertIsInstance(prop.value, JsFunctionExpression)

    def test_method_named_set(self):
        expr = self._parse_expr('({ set(v) {} })')
        obj = expr.expression
        prop = obj.properties[0]
        self.assertIsInstance(prop, JsProperty)
        self.assertTrue(prop.method)
        self.assertFalse(prop.shorthand)
        self.assertEqual(prop.kind, JsPropertyKind.INIT)
        self.assertIsInstance(prop.key, JsIdentifier)
        self.assertEqual(prop.key.name, 'set')

    def test_generator_method_named_get(self):
        expr = self._parse_expr('({ *get() { yield 1; } })')
        obj = expr.expression
        prop = obj.properties[0]
        self.assertIsInstance(prop, JsProperty)
        self.assertTrue(prop.method)
        self.assertEqual(prop.kind, JsPropertyKind.INIT)
        self.assertIsInstance(prop.key, JsIdentifier)
        self.assertEqual(prop.key.name, 'get')
        self.assertIsInstance(prop.value, JsFunctionExpression)
        self.assertTrue(prop.value.generator)

    def test_generator_method_named_set(self):
        expr = self._parse_expr('({ *set() { yield 1; } })')
        obj = expr.expression
        prop = obj.properties[0]
        self.assertEqual(prop.kind, JsPropertyKind.INIT)
        self.assertIsInstance(prop.key, JsIdentifier)
        self.assertEqual(prop.key.name, 'set')
        self.assertTrue(prop.value.generator)

    def test_async_call_is_not_sequence(self):
        expr = self._parse_expr('async(1, 2)')
        self.assertIsInstance(expr, JsCallExpression)
        self.assertIsInstance(expr.callee, JsIdentifier)
        self.assertEqual(expr.callee.name, 'async')
        self.assertEqual(len(expr.arguments), 2)

    def test_async_empty_call(self):
        expr = self._parse_expr('async()')
        self.assertIsInstance(expr, JsCallExpression)
        self.assertIsInstance(expr.callee, JsIdentifier)
        self.assertEqual(expr.callee.name, 'async')
        self.assertEqual(len(expr.arguments), 0)

    def test_async_member_call(self):
        expr = self._parse_expr('async.foo()')
        self.assertIsInstance(expr, JsCallExpression)
        self.assertIsInstance(expr.callee, JsMemberExpression)
        self.assertIsInstance(expr.callee.object, JsIdentifier)
        self.assertEqual(expr.callee.object.name, 'async')

    def test_async_is_identifier_in_binary(self):
        expr = self._parse_expr('async + 1')
        self.assertIsInstance(expr, JsBinaryExpression)
        self.assertIsInstance(expr.left, JsIdentifier)
        self.assertEqual(expr.left.name, 'async')

    def test_async_bare_identifier(self):
        expr = self._parse_expr('async')
        self.assertIsInstance(expr, JsIdentifier)
        self.assertEqual(expr.name, 'async')

    def test_async_arrow_paren_param(self):
        expr = self._parse_expr('async(x) => x')
        self.assertIsInstance(expr, JsArrowFunctionExpression)
        self.assertTrue(expr.is_async)
        self.assertEqual(len(expr.params), 1)

    def test_async_arrow_bare_param(self):
        expr = self._parse_expr('async x => x')
        self.assertIsInstance(expr, JsArrowFunctionExpression)
        self.assertTrue(expr.is_async)
        self.assertEqual(len(expr.params), 1)

    def test_async_is_param_name_in_sync_arrow(self):
        expr = self._parse_expr('async => async + 1')
        self.assertIsInstance(expr, JsArrowFunctionExpression)
        self.assertFalse(expr.is_async)
        self.assertEqual(len(expr.params), 1)
        self.assertIsInstance(expr.params[0], JsIdentifier)
        self.assertEqual(expr.params[0].name, 'async')

    def test_async_arrow_contextual_keyword_param(self):
        expr = self._parse_expr('async of => of')
        self.assertIsInstance(expr, JsArrowFunctionExpression)
        self.assertTrue(expr.is_async)
        self.assertEqual(len(expr.params), 1)
        self.assertIsInstance(expr.params[0], JsIdentifier)
        self.assertEqual(expr.params[0].name, 'of')

    def test_new_async_is_construct_not_call(self):
        expr = self._parse_expr('new async()')
        self.assertIsInstance(expr, JsNewExpression)
        self.assertIsInstance(expr.callee, JsIdentifier)
        self.assertEqual(expr.callee.name, 'async')
        self.assertEqual(len(expr.arguments), 0)

    def test_new_async_with_arguments(self):
        expr = self._parse_expr('new async(1, 2)')
        self.assertIsInstance(expr, JsNewExpression)
        self.assertIsInstance(expr.callee, JsIdentifier)
        self.assertEqual(expr.callee.name, 'async')
        self.assertEqual(len(expr.arguments), 2)

    def test_new_async_member_callee(self):
        expr = self._parse_expr('new async.foo()')
        self.assertIsInstance(expr, JsNewExpression)
        self.assertIsInstance(expr.callee, JsMemberExpression)
