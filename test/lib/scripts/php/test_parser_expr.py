from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.php.model import (
    PhpArray,
    PhpArrayDimFetch,
    PhpArrowFunction,
    PhpAssignment,
    PhpBinaryExpression,
    PhpBooleanLiteral,
    PhpCastExpression,
    PhpClassConstFetch,
    PhpClone,
    PhpClosure,
    PhpConstFetch,
    PhpEmpty,
    PhpErrorSuppress,
    PhpExpressionStatement,
    PhpFloatLiteral,
    PhpFunctionCall,
    PhpInstanceof,
    PhpIntLiteral,
    PhpInterpolatedString,
    PhpIsset,
    PhpMatch,
    PhpMethodCall,
    PhpNew,
    PhpNullLiteral,
    PhpPropertyFetch,
    PhpStaticCall,
    PhpStringLiteral,
    PhpTernary,
    PhpUnaryExpression,
    PhpUpdateExpression,
    PhpVariable,
)
from refinery.lib.scripts.php.parser import PhpParser


class TestPhpParserExpr(TestBase):

    def _expr(self, code: str):
        ast = PhpParser(F'<?php {code};').parse()
        self.assertEqual(len(ast.body), 1)
        stmt = ast.body[0]
        self.assertIsInstance(stmt, PhpExpressionStatement)
        return stmt.expression

    def test_int_literal(self):
        node = self._expr('42')
        self.assertIsInstance(node, PhpIntLiteral)
        self.assertEqual(node.value, 42)

    def test_hex_literal(self):
        node = self._expr('0xFF')
        self.assertIsInstance(node, PhpIntLiteral)
        self.assertEqual(node.value, 255)

    def test_float_literal(self):
        node = self._expr('3.5')
        self.assertIsInstance(node, PhpFloatLiteral)
        self.assertEqual(node.value, 3.5)

    def test_string_literal_single(self):
        node = self._expr("'hi'")
        self.assertIsInstance(node, PhpStringLiteral)
        self.assertEqual(node.value, 'hi')

    def test_string_literal_double_plain(self):
        node = self._expr('"hi"')
        self.assertIsInstance(node, PhpStringLiteral)
        self.assertEqual(node.value, 'hi')

    def test_interpolated_string(self):
        node = self._expr('"hi $name"')
        self.assertIsInstance(node, PhpInterpolatedString)

    def test_boolean_true(self):
        node = self._expr('true')
        self.assertIsInstance(node, PhpBooleanLiteral)
        self.assertEqual(node.value, True)

    def test_null(self):
        node = self._expr('null')
        self.assertIsInstance(node, PhpNullLiteral)

    def test_variable(self):
        node = self._expr('$x')
        self.assertIsInstance(node, PhpVariable)
        self.assertEqual(node.name, '$x')

    def test_addition(self):
        node = self._expr('1 + 2')
        self.assertIsInstance(node, PhpBinaryExpression)
        self.assertEqual(node.operator, '+')

    def test_precedence_mul_over_add(self):
        node = self._expr('1 + 2 * 3')
        self.assertIsInstance(node, PhpBinaryExpression)
        self.assertEqual(node.operator, '+')
        self.assertIsInstance(node.right, PhpBinaryExpression)
        self.assertEqual(node.right.operator, '*')

    def test_precedence_concat_below_add(self):
        node = self._expr('"a" . 1 + 2')
        self.assertIsInstance(node, PhpBinaryExpression)
        self.assertEqual(node.operator, '.')
        self.assertIsInstance(node.right, PhpBinaryExpression)
        self.assertEqual(node.right.operator, '+')

    def test_pow_right_associative(self):
        node = self._expr('2 ** 3 ** 2')
        self.assertIsInstance(node, PhpBinaryExpression)
        self.assertEqual(node.operator, '**')
        self.assertIsInstance(node.right, PhpBinaryExpression)
        self.assertEqual(node.right.operator, '**')

    def test_coalesce_right_associative(self):
        node = self._expr('$a ?? $b ?? $c')
        self.assertIsInstance(node, PhpBinaryExpression)
        self.assertEqual(node.operator, '??')
        self.assertIsInstance(node.right, PhpBinaryExpression)
        self.assertEqual(node.right.operator, '??')

    def test_assignment(self):
        node = self._expr('$x = 5')
        self.assertIsInstance(node, PhpAssignment)
        self.assertEqual(node.operator, '=')

    def test_assignment_by_ref(self):
        node = self._expr('$x = &$y')
        self.assertIsInstance(node, PhpAssignment)
        self.assertEqual(node.by_ref, True)

    def test_compound_assignment(self):
        node = self._expr('$x .= $y')
        self.assertIsInstance(node, PhpAssignment)
        self.assertEqual(node.operator, '.=')

    def test_ternary(self):
        node = self._expr('$a ? $b : $c')
        self.assertIsInstance(node, PhpTernary)

    def test_short_ternary(self):
        node = self._expr('$a ?: $c')
        self.assertIsInstance(node, PhpTernary)
        self.assertEqual(node.consequent, None)

    def test_unary_not(self):
        node = self._expr('!$x')
        self.assertIsInstance(node, PhpUnaryExpression)
        self.assertEqual(node.operator, '!')

    def test_unary_minus(self):
        node = self._expr('-$x')
        self.assertIsInstance(node, PhpUnaryExpression)
        self.assertEqual(node.operator, '-')

    def test_prefix_increment(self):
        node = self._expr('++$x')
        self.assertIsInstance(node, PhpUpdateExpression)
        self.assertEqual(node.prefix, True)

    def test_postfix_increment(self):
        node = self._expr('$x++')
        self.assertIsInstance(node, PhpUpdateExpression)
        self.assertEqual(node.prefix, False)

    def test_cast(self):
        node = self._expr('(int) $x')
        self.assertIsInstance(node, PhpCastExpression)
        self.assertEqual(node.cast, 'int')

    def test_error_suppress(self):
        node = self._expr('@foo()')
        self.assertIsInstance(node, PhpErrorSuppress)

    def test_clone(self):
        node = self._expr('clone $x')
        self.assertIsInstance(node, PhpClone)

    def test_instanceof(self):
        node = self._expr('$x instanceof Foo')
        self.assertIsInstance(node, PhpInstanceof)

    def test_function_call(self):
        node = self._expr('foo($a, $b)')
        self.assertIsInstance(node, PhpFunctionCall)
        self.assertEqual(len(node.args), 2)

    def test_function_call_named_arg(self):
        node = self._expr('foo(name: $b)')
        self.assertIsInstance(node, PhpFunctionCall)
        self.assertEqual(node.args[0].name, 'name')

    def test_first_class_callable(self):
        node = self._expr('strlen(...)')
        self.assertIsInstance(node, PhpFunctionCall)
        self.assertEqual(node.first_class_callable, True)

    def test_method_call(self):
        node = self._expr('$obj->method()')
        self.assertIsInstance(node, PhpMethodCall)
        self.assertEqual(node.nullsafe, False)

    def test_nullsafe_method_call(self):
        node = self._expr('$obj?->method()')
        self.assertIsInstance(node, PhpMethodCall)
        self.assertEqual(node.nullsafe, True)

    def test_property_fetch(self):
        node = self._expr('$obj->prop')
        self.assertIsInstance(node, PhpPropertyFetch)

    def test_static_call(self):
        node = self._expr('Foo::bar()')
        self.assertIsInstance(node, PhpStaticCall)

    def test_class_const_fetch(self):
        node = self._expr('Foo::BAR')
        self.assertIsInstance(node, PhpClassConstFetch)

    def test_array_dim_fetch(self):
        node = self._expr('$a[0]')
        self.assertIsInstance(node, PhpArrayDimFetch)

    def test_short_array(self):
        node = self._expr('[1, 2, 3]')
        self.assertIsInstance(node, PhpArray)
        self.assertEqual(node.short, True)
        self.assertEqual(len(node.items), 3)

    def test_long_array(self):
        node = self._expr('array(1, 2)')
        self.assertIsInstance(node, PhpArray)
        self.assertEqual(node.short, False)

    def test_array_with_keys(self):
        node = self._expr('["a" => 1]')
        self.assertIsInstance(node, PhpArray)
        self.assertIsInstance(node.items[0].key, PhpStringLiteral)

    def test_new(self):
        node = self._expr('new Foo($x)')
        self.assertIsInstance(node, PhpNew)
        self.assertEqual(len(node.args), 1)

    def test_closure(self):
        node = self._expr('function ($x) use ($y) { return $x; }')
        self.assertIsInstance(node, PhpClosure)
        self.assertEqual(len(node.params), 1)
        self.assertEqual(len(node.uses), 1)

    def test_arrow_function(self):
        node = self._expr('fn($x) => $x * 2')
        self.assertIsInstance(node, PhpArrowFunction)

    def test_match(self):
        node = self._expr('match($x) { 1 => "a", default => "b" }')
        self.assertIsInstance(node, PhpMatch)
        self.assertEqual(len(node.arms), 2)

    def test_isset(self):
        node = self._expr('isset($a, $b)')
        self.assertIsInstance(node, PhpIsset)
        self.assertEqual(len(node.variables), 2)

    def test_empty(self):
        node = self._expr('empty($a)')
        self.assertIsInstance(node, PhpEmpty)

    def test_const_fetch(self):
        node = self._expr('PHP_EOL')
        self.assertIsInstance(node, PhpConstFetch)

    def test_instanceof_non_associative(self):
        # PHP declares instanceof as non-associative: $a instanceof B instanceof C
        # must parse as ($a instanceof B) with the second instanceof left unconsumed.
        from refinery.lib.scripts.php.model import PhpExpressionStatement
        ast = PhpParser('<?php $a instanceof B instanceof C;').parse()
        stmts = ast.body
        # Should produce two statements or error nodes rather than nested instanceof.
        first = stmts[0]
        self.assertIsInstance(first, PhpExpressionStatement)
        self.assertIsInstance(first.expression, PhpInstanceof)
        # The second instanceof should NOT be nested inside the first.
        self.assertNotIsInstance(first.expression.operand, PhpInstanceof)

    def test_comparison_non_associative(self):
        # PHP declares < as non-associative: $a < $b < $c must not produce
        # a nested left-associative binary expression.
        ast = PhpParser('<?php $a < $b < $c;').parse()
        stmts = ast.body
        # The parser should not produce a clean nested PhpBinaryExpression
        # for $a < $b < $c; it breaks after one operator.
        first = stmts[0]
        self.assertIsInstance(first, PhpExpressionStatement)
        inner = first.expression
        self.assertIsInstance(inner, PhpBinaryExpression)
        # Left operand must be a variable ($a), not a comparison (would mean chaining).
        self.assertNotIsInstance(inner.left, PhpBinaryExpression)
