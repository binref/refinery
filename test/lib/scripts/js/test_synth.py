from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer


class TestJsSynthesizer(TestBase):

    def _round_trip(self, source: str):
        synth = JsSynthesizer()
        ast1 = JsParser(source).parse()
        out1 = synth.convert(ast1)
        ast2 = JsParser(out1).parse()
        out2 = synth.convert(ast2)
        self.assertEqual(
            out1, out2,
            F'Round-trip failed:\nInput: {source!r}\nFirst: {out1!r}\nSecond: {out2!r}',
        )
        return out1

    def test_numeric_literal(self):
        self._round_trip('42;')

    def test_float_literal(self):
        self._round_trip('3.14;')

    def test_hex_literal(self):
        self._round_trip('0xFF;')

    def test_string_literal_single(self):
        self._round_trip("'hello';")

    def test_string_literal_double(self):
        self._round_trip('"world";')

    def test_boolean_true(self):
        self._round_trip('true;')

    def test_boolean_false(self):
        self._round_trip('false;')

    def test_null_literal(self):
        self._round_trip('null;')

    def test_regex_literal(self):
        self._round_trip('/abc/gi;')

    def test_template_simple(self):
        self._round_trip('`hello`;')

    def test_template_expression(self):
        self._round_trip('`hello ${name}`;')

    def test_this_expression(self):
        self._round_trip('this;')

    def test_identifier(self):
        self._round_trip('foo;')

    def test_binary_expression(self):
        self._round_trip('a + b;')

    def test_binary_multiply(self):
        self._round_trip('x * y;')

    def test_unary_typeof(self):
        self._round_trip('typeof x;')

    def test_unary_not(self):
        self._round_trip('!x;')

    def test_unary_void(self):
        self._round_trip('void 0;')

    def test_update_prefix(self):
        self._round_trip('++i;')

    def test_update_postfix(self):
        self._round_trip('i++;')

    def test_member_dot(self):
        self._round_trip('obj.prop;')

    def test_member_bracket(self):
        self._round_trip('obj["prop"];')

    def test_member_optional(self):
        self._round_trip('obj?.prop;')

    def test_call_expression(self):
        self._round_trip('foo(a, b);')

    def test_call_optional(self):
        self._round_trip('foo?.(a);')

    def test_new_expression(self):
        self._round_trip('new Foo(a, b);')

    def test_array_expression(self):
        self._round_trip('[1, 2, 3];')

    def test_object_expression(self):
        self._round_trip('({ a: 1, b: 2 });')

    def test_object_shorthand(self):
        self._round_trip('({ x });')

    def test_spread_element(self):
        self._round_trip('[...arr];')

    def test_assignment(self):
        self._round_trip('x = 5;')

    def test_conditional(self):
        self._round_trip('a ? b : c;')

    def test_logical_and(self):
        self._round_trip('a && b;')

    def test_logical_or(self):
        self._round_trip('a || b;')

    def test_sequence(self):
        self._round_trip('(a, b, c);')

    def test_arrow_single_param(self):
        self._round_trip('x => x;')

    def test_arrow_multi_param(self):
        self._round_trip('(a, b) => a + b;')

    def test_arrow_block_body(self):
        self._round_trip('(x) => { return x; };')

    def test_arrow_no_params(self):
        self._round_trip('() => 42;')

    def test_function_expression(self):
        self._round_trip('(function() {});')

    def test_function_expression_named(self):
        self._round_trip('(function foo(a) { return a; });')

    def test_function_declaration(self):
        self._round_trip('function foo(a, b) { return a + b; }')

    def test_async_function(self):
        self._round_trip('async function foo() { return 1; }')

    def test_generator_function(self):
        self._round_trip('function* gen() { yield 1; }')

    def test_class_declaration(self):
        self._round_trip('class Foo { constructor() {} }')

    def test_class_extends(self):
        self._round_trip('class Foo extends Bar { method() {} }')

    def test_class_static_method(self):
        self._round_trip('class C { static create() {} }')

    def test_class_getter_setter(self):
        self._round_trip('class C { get x() {} set x(v) {} }')

    def test_variable_var(self):
        self._round_trip('var x = 1;')

    def test_variable_let(self):
        self._round_trip('let x = 1;')

    def test_variable_const(self):
        self._round_trip('const x = 1;')

    def test_variable_destructuring_array(self):
        self._round_trip('let [a, b] = arr;')

    def test_variable_destructuring_object(self):
        self._round_trip('let { a, b } = obj;')

    def test_if_statement(self):
        self._round_trip('if (x) { y; }')

    def test_if_else(self):
        self._round_trip('if (x) { y; } else { z; }')

    def test_while_statement(self):
        self._round_trip('while (true) { break; }')

    def test_do_while(self):
        self._round_trip('do { x++; } while (x < 10);')

    def test_for_statement(self):
        self._round_trip('for (var i = 0; i < 10; i++) { x; }')

    def test_for_in(self):
        self._round_trip('for (var k in obj) { k; }')

    def test_for_in_no_var(self):
        self._round_trip('for (x in obj) { x; }')

    def test_for_of(self):
        self._round_trip('for (const x of arr) { x; }')

    def test_switch_statement(self):
        result = self._round_trip('switch (x) { case 1: a; break; default: b; }')
        self.assertIn('case', result)
        self.assertIn('default', result)

    def test_try_catch(self):
        self._round_trip('try { x; } catch (e) { y; }')

    def test_try_catch_finally(self):
        self._round_trip('try { x; } catch (e) { y; } finally { z; }')

    def test_throw_statement(self):
        self._round_trip('throw new Error("x");')

    def test_return_statement(self):
        self._round_trip('function f() { return 1; }')

    def test_return_no_arg(self):
        self._round_trip('function f() { return; }')

    def test_break_statement(self):
        self._round_trip('while (true) { break; }')

    def test_break_label(self):
        self._round_trip('outer: while (true) { break outer; }')

    def test_continue_statement(self):
        self._round_trip('while (true) { continue; }')

    def test_labeled_statement(self):
        self._round_trip('loop: for (;;) { break loop; }')

    def test_with_statement(self):
        self._round_trip('with (obj) { x; }')

    def test_debugger(self):
        self._round_trip('debugger;')

    def test_empty_statement(self):
        self._round_trip(';')

    def test_import_default(self):
        self._round_trip("import foo from 'bar';")

    def test_import_named(self):
        self._round_trip("import { a, b } from 'mod';")

    def test_import_namespace(self):
        self._round_trip("import * as ns from 'mod';")

    def test_import_bare(self):
        self._round_trip("import 'mod';")

    def test_export_named(self):
        self._round_trip('export { a, b };')

    def test_export_default(self):
        self._round_trip('export default 42;')

    def test_export_declaration(self):
        self._round_trip('export const x = 1;')

    def test_export_all(self):
        self._round_trip("export * from 'mod';")

    def test_await_expression(self):
        self._round_trip('async function f() { await x; }')

    def test_yield_expression(self):
        self._round_trip('function* g() { yield 1; }')

    def test_yield_delegate(self):
        self._round_trip('function* g() { yield* other(); }')

    def test_tagged_template(self):
        self._round_trip('tag`hello`;')

    def test_paren_expression(self):
        self._round_trip('(a + b);')

    def test_rest_element(self):
        self._round_trip('function f(...args) {}')

    def test_assignment_pattern_default(self):
        self._round_trip('function f(a = 1) {}')

    def test_property_definition(self):
        self._round_trip('class C { x = 5; }')

    def test_bigint_literal(self):
        self._round_trip('100n;')

    def test_multiline_script(self):
        self._round_trip('var a = 1;\nvar b = 2;\nvar c = a + b;')

    def test_nested_calls(self):
        self._round_trip('a(b(c(d)));')

    def test_chained_member_access(self):
        self._round_trip('a.b.c.d;')
