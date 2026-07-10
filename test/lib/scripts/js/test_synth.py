from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.js.model import (
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsAssignmentPattern,
    JsAwaitExpression,
    JsBinaryExpression,
    JsBlockStatement,
    JsCallExpression,
    JsClassBody,
    JsClassExpression,
    JsConditionalExpression,
    JsExpressionStatement,
    JsFunctionExpression,
    JsIdentifier,
    JsLogicalExpression,
    JsMemberExpression,
    JsNumericLiteral,
    JsObjectExpression,
    JsObjectPattern,
    JsProperty,
    JsPropertyDefinition,
    JsScript,
    JsSequenceExpression,
    JsSpreadElement,
    JsTaggedTemplateExpression,
    JsTemplateElement,
    JsTemplateLiteral,
    JsUpdateExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsVarKind,
    JsYieldExpression,
)
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

    def test_object_method(self):
        self._round_trip('({ foo() {} });')

    def test_object_getter(self):
        self._round_trip('({ get x() {} });')

    def test_object_setter(self):
        self._round_trip('({ set x(v) {} });')

    def test_object_generator_method(self):
        self._round_trip('({ *foo() { yield 1; } });')

    def test_object_async_method(self):
        self._round_trip('({ async foo() { await bar(); } });')

    def test_object_method_named_get(self):
        self.assertEqual('({ get() {} });', self._round_trip('({ get() {} });'))

    def test_object_method_named_set(self):
        self.assertEqual('({ set(v) {} });', self._round_trip('({ set(v) {} });'))

    def test_object_generator_method_named_get(self):
        self.assertEqual('({ *get() {} });', self._round_trip('({ *get() {} });'))

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

    def test_class_generator_method(self):
        self._round_trip('class C { *gen() { yield 1; } }')

    def test_class_async_method(self):
        self._round_trip('class C { async fetch() { await req(); } }')

    def test_class_async_generator_method(self):
        self._round_trip('class C { async *stream() { yield 1; } }')

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

    def test_return_wrapping_sequence_no_asi(self):
        filler = 'A' * 160
        source = "function f() { return '%s' + tail, sendStorage(value); }" % filler
        out = self._round_trip(source)
        self.assertNotRegex(out, r'return[ \t]*\n')
        self.assertIn('sendStorage(value)', out)

    def test_negative_number_operand_after_newline(self):
        source = 'x = f(\n  alphaaaaaaaaa,\n  -680876936\n);'
        out = JsSynthesizer().convert(JsParser(source).parse())
        self.assertIn('-680876936', out)

    def _assert_synth_valid(self, node, expected: str):
        out = JsSynthesizer().convert(node)
        self.assertEqual(expected, out)
        statement = out if out.endswith(';') else out + ';'
        self.assertEqual(statement, JsSynthesizer().convert(JsParser(out).parse()))

    def test_paren_arrow_in_callee_position(self):
        arrow = JsArrowFunctionExpression(params=[], body=JsIdentifier(name='x'))
        self._assert_synth_valid(JsCallExpression(callee=arrow, arguments=[]), '(() => x)()')

    def test_paren_arrow_in_member_object(self):
        arrow = JsArrowFunctionExpression(params=[], body=JsIdentifier(name='x'))
        node = JsMemberExpression(object=arrow, property=JsIdentifier(name='foo'), computed=False)
        self._assert_synth_valid(node, '(() => x).foo')

    def test_paren_binary_in_member_object(self):
        binop = JsBinaryExpression(
            left=JsIdentifier(name='a'), operator='+', right=JsIdentifier(name='b'))
        node = JsMemberExpression(object=binop, property=JsIdentifier(name='c'), computed=False)
        self._assert_synth_valid(node, '(a + b).c')

    def test_paren_sequence_as_call_argument(self):
        seq = JsSequenceExpression(
            expressions=[JsIdentifier(name='a'), JsIdentifier(name='b')])
        node = JsCallExpression(callee=JsIdentifier(name='f'), arguments=[seq])
        self._assert_synth_valid(node, 'f((a, b))')

    def test_paren_arrow_object_body(self):
        node = JsArrowFunctionExpression(params=[], body=JsObjectExpression(properties=[]))
        self._assert_synth_valid(node, '() => ({})')

    def test_paren_function_expression_at_statement_start(self):
        fn = JsFunctionExpression(params=[], body=JsBlockStatement(body=[]))
        call = JsCallExpression(callee=fn, arguments=[])
        script = JsScript(body=[JsExpressionStatement(expression=call)])
        self._assert_synth_valid(script, '(function() {}());')

    def test_paren_arrow_body_object_on_left_spine(self):
        body = JsMemberExpression(
            object=JsObjectExpression(properties=[]),
            property=JsIdentifier(name='x'),
            computed=False,
        )
        self._assert_synth_valid(
            JsArrowFunctionExpression(params=[], body=body), '() => ({}.x)')

    def test_paren_arrow_body_function_on_left_spine(self):
        fn = JsFunctionExpression(params=[], body=JsBlockStatement(body=[]))
        body = JsCallExpression(callee=fn, arguments=[])
        self._assert_synth_valid(
            JsArrowFunctionExpression(params=[], body=body), '() => (function() {}())')

    def test_paren_await_of_binary(self):
        node = JsAwaitExpression(argument=JsBinaryExpression(
            left=JsIdentifier(name='a'), operator='+', right=JsIdentifier(name='b')))
        self.assertEqual('await (a + b)', JsSynthesizer().convert(node))

    def test_paren_member_on_await(self):
        node = JsMemberExpression(
            object=JsAwaitExpression(argument=JsIdentifier(name='a')),
            property=JsIdentifier(name='b'),
            computed=False,
        )
        self.assertEqual('(await a).b', JsSynthesizer().convert(node))

    def test_paren_sequence_in_conditional_alternate(self):
        seq = JsSequenceExpression(
            expressions=[JsIdentifier(name='c'), JsIdentifier(name='d')])
        node = JsConditionalExpression(
            test=JsIdentifier(name='a'), consequent=JsIdentifier(name='b'), alternate=seq)
        self._assert_synth_valid(node, 'a ? b : (c, d)')

    def test_paren_operator_tag_of_tagged_template(self):
        quasi = JsTemplateLiteral(quasis=[JsTemplateElement(value='x')], expressions=[])
        tag = JsBinaryExpression(
            left=JsIdentifier(name='a'), operator='+', right=JsIdentifier(name='b'))
        self._assert_synth_valid(JsTaggedTemplateExpression(tag=tag, quasi=quasi), '(a + b)`x`')

    def test_paren_nullish_nested_under_logical_or(self):
        coalesce = JsLogicalExpression(
            left=JsIdentifier(name='a'), operator='??', right=JsIdentifier(name='b'))
        node = JsLogicalExpression(left=coalesce, operator='||', right=JsIdentifier(name='c'))
        self._assert_synth_valid(node, '(a ?? b) || c')

    def test_paren_logical_and_nested_under_nullish(self):
        conjunction = JsLogicalExpression(
            left=JsIdentifier(name='b'), operator='&&', right=JsIdentifier(name='c'))
        node = JsLogicalExpression(left=JsIdentifier(name='a'), operator='??', right=conjunction)
        self._assert_synth_valid(node, 'a ?? (b && c)')

    def test_no_paren_nullish_chain(self):
        coalesce = JsLogicalExpression(
            left=JsIdentifier(name='a'), operator='??', right=JsIdentifier(name='b'))
        node = JsLogicalExpression(left=coalesce, operator='??', right=JsIdentifier(name='c'))
        self._assert_synth_valid(node, 'a ?? b ?? c')

    def test_paren_prefix_update_as_exponent_left_operand(self):
        node = JsBinaryExpression(
            left=JsUpdateExpression(prefix=True, operator='++', argument=JsIdentifier(name='x')),
            operator='**',
            right=JsNumericLiteral(value=2, raw='2'),
        )
        self._assert_synth_valid(node, '(++x) ** 2')

    def test_paren_await_as_exponent_left_operand(self):
        node = JsBinaryExpression(
            left=JsAwaitExpression(argument=JsIdentifier(name='x')),
            operator='**',
            right=JsNumericLiteral(value=2, raw='2'),
        )
        self.assertEqual('(await x) ** 2', JsSynthesizer().convert(node))

    def test_paren_sequence_as_yield_argument(self):
        seq = JsSequenceExpression(expressions=[JsIdentifier(name='a'), JsIdentifier(name='b')])
        node = JsYieldExpression(argument=seq, delegate=False)
        self.assertEqual('yield (a, b)', JsSynthesizer().convert(node))

    def test_paren_sequence_as_spread_argument(self):
        seq = JsSequenceExpression(expressions=[JsIdentifier(name='a'), JsIdentifier(name='b')])
        node = JsCallExpression(
            callee=JsIdentifier(name='f'),
            arguments=[JsSpreadElement(argument=seq)],
        )
        self._assert_synth_valid(node, 'f(...(a, b))')

    def test_paren_sequence_as_variable_init(self):
        seq = JsSequenceExpression(expressions=[JsIdentifier(name='a'), JsIdentifier(name='b')])
        node = JsVariableDeclaration(
            kind=JsVarKind.VAR,
            declarations=[JsVariableDeclarator(id=JsIdentifier(name='x'), init=seq)],
        )
        self._assert_synth_valid(node, 'var x = (a, b);')

    def test_paren_sequence_as_assignment_pattern_default(self):
        seq = JsSequenceExpression(expressions=[JsIdentifier(name='a'), JsIdentifier(name='b')])
        node = JsFunctionExpression(
            params=[JsAssignmentPattern(left=JsIdentifier(name='x'), right=seq)],
            body=JsBlockStatement(body=[]),
        )
        self.assertEqual('function(x = (a, b)) {}', JsSynthesizer().convert(node))

    def test_paren_sequence_as_property_value(self):
        seq = JsSequenceExpression(expressions=[JsIdentifier(name='a'), JsIdentifier(name='b')])
        node = JsObjectExpression(properties=[JsProperty(key=JsIdentifier(name='k'), value=seq)])
        self.assertIn('k: (a, b)', JsSynthesizer().convert(node))

    def test_paren_sequence_as_class_field_value(self):
        seq = JsSequenceExpression(expressions=[JsIdentifier(name='a'), JsIdentifier(name='b')])
        node = JsClassExpression(body=JsClassBody(body=[
            JsPropertyDefinition(key=JsIdentifier(name='x'), value=seq),
        ]))
        self.assertIn('x = (a, b);', JsSynthesizer().convert(node))

    def test_paren_prefix_update_in_member_object(self):
        node = JsMemberExpression(
            object=JsUpdateExpression(prefix=True, operator='++', argument=JsIdentifier(name='x')),
            property=JsIdentifier(name='foo'),
            computed=False,
        )
        self._assert_synth_valid(node, '(++x).foo')

    def test_paren_postfix_update_in_member_object(self):
        node = JsMemberExpression(
            object=JsUpdateExpression(prefix=False, operator='++', argument=JsIdentifier(name='x')),
            property=JsIdentifier(name='foo'),
            computed=False,
        )
        self._assert_synth_valid(node, '(x++).foo')

    def test_no_paren_postfix_update_as_exponent_left_operand(self):
        node = JsBinaryExpression(
            left=JsUpdateExpression(prefix=False, operator='++', argument=JsIdentifier(name='x')),
            operator='**',
            right=JsNumericLiteral(value=2, raw='2'),
        )
        self._assert_synth_valid(node, 'x++ ** 2')

    def test_paren_sequence_in_conditional_consequent(self):
        seq = JsSequenceExpression(
            expressions=[JsIdentifier(name='b'), JsIdentifier(name='c')])
        node = JsConditionalExpression(
            test=JsIdentifier(name='a'), consequent=seq, alternate=JsIdentifier(name='d'))
        self._assert_synth_valid(node, 'a ? (b, c) : d')

    def test_paren_arrow_as_binary_left_operand(self):
        arrow = JsArrowFunctionExpression(params=[], body=JsIdentifier(name='x'))
        node = JsBinaryExpression(left=arrow, operator='+', right=JsIdentifier(name='b'))
        self._assert_synth_valid(node, '(() => x) + b')

    def test_paren_arrow_as_binary_right_operand(self):
        arrow = JsArrowFunctionExpression(params=[], body=JsIdentifier(name='x'))
        node = JsBinaryExpression(
            left=JsIdentifier(name='a'), operator='&&', right=arrow)
        self._assert_synth_valid(node, 'a && (() => x)')

    def test_paren_assignment_as_binary_right_operand(self):
        assign = JsAssignmentExpression(
            left=JsIdentifier(name='b'), operator='=', right=JsIdentifier(name='c'))
        node = JsBinaryExpression(left=JsIdentifier(name='a'), operator='+', right=assign)
        self._assert_synth_valid(node, 'a + (b = c)')

    def test_paren_same_precedence_right_operand(self):
        inner = JsBinaryExpression(
            left=JsIdentifier(name='b'), operator='-', right=JsIdentifier(name='c'))
        node = JsBinaryExpression(left=JsIdentifier(name='a'), operator='-', right=inner)
        self._assert_synth_valid(node, 'a - (b - c)')

    def test_paren_arrow_body_destructuring_assignment(self):
        body = JsAssignmentExpression(
            left=JsObjectPattern(properties=[
                JsProperty(
                    key=JsIdentifier(name='a'),
                    value=JsIdentifier(name='a'),
                    shorthand=True,
                ),
            ]),
            operator='=',
            right=JsIdentifier(name='obj'),
        )
        node = JsArrowFunctionExpression(params=[], body=body)
        self._assert_synth_valid(node, '() => ({ a } = obj)')

    def test_break_statement(self):
        self._round_trip('outer: while (true) { break outer; }')

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
        self._round_trip('function* g() { var x = yield 1; }')

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

    def test_object_pattern_shorthand_default_var(self):
        self.assertEqual(self._round_trip('var {a = d} = o;'), 'var { a = d } = o;')

    def test_object_pattern_shorthand_default_const(self):
        self.assertEqual(self._round_trip('const {a = d} = o;'), 'const { a = d } = o;')

    def test_object_pattern_shorthand_default_param(self):
        self.assertEqual(self._round_trip('function f({a = d}) {}'), 'function f({ a = d }) {}')

    def test_object_pattern_shorthand_default_mixed_with_plain(self):
        self.assertEqual(self._round_trip('var {a = d, b} = o;'), 'var { a = d, b } = o;')

    def test_object_pattern_shorthand_default_nested(self):
        self.assertEqual(self._round_trip('var {a: {b = d}} = o;'), 'var { a: { b = d } } = o;')

    def test_object_assignment_pattern_shorthand_default(self):
        self.assertEqual(self._round_trip('({a = d} = o);'), '({ a = d } = o);')

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

    def test_private_field(self):
        self._round_trip('class A { #x = 1; }')

    def test_private_method_and_access(self):
        self._round_trip('class A { #x = 2; #m() { return this.#x; } }')

    def test_private_brand_check(self):
        self._round_trip('class A { #x; has(o) { return #x in o; } }')

    def test_static_private_field(self):
        self._round_trip('class A { static #n = 0; }')

    def test_static_block(self):
        self._round_trip('class A { static { this.x = 1; } }')

    def test_static_block_with_var_and_loop(self):
        self._round_trip('class A { static { var t = 0; for (var i = 0; i < 3; i++) t += i; } }')

    def test_static_field_named_static(self):
        self._round_trip('class A { static x = 1; }')

    def test_dynamic_import(self):
        self._round_trip("import('m');")

    def test_dynamic_import_with_options(self):
        self._round_trip("import('m', { with: { type: 'json' } });")

    def test_dynamic_import_postfix(self):
        self._round_trip("import('a').then(f);")

    def test_import_meta(self):
        self._round_trip('var u = import.meta.url;')

    def test_import_with_attributes(self):
        self._round_trip("import x from 'y' with { type: 'json' };")

    def test_class_decorator(self):
        self._round_trip('@dec class C {}')

    def test_class_decorator_call(self):
        self._round_trip('@dec(1) class C {}')

    def test_class_decorator_member(self):
        self._round_trip('@a.b.c class C {}')

    def test_member_decorators(self):
        self._round_trip('class C { @a m() {} @b x = 1; }')

    def test_export_decorated_class(self):
        self._round_trip('export @dec class C {}')
