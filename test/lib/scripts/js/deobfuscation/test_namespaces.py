from __future__ import annotations

import inspect
import unittest

from test import backlog, opportunity
from test.lib.scripts.js.analysis.differential import behavior, node_executable
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator
from test.lib.scripts.js.ledger import before_and_after, before_and_after_in_a_host, prints

from refinery.lib.scripts.js.deobfuscation.namespaces import JsNamespaceFlattening
from refinery.lib.scripts.js.options import DeobfuscationOptions
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer

A_READ_INSIDE_A_FUNCTION_BINDING_THE_NAMESPACES_NAME = {
    'an outer namespace a bare read keeps': (
        'var A = {}; function f() { var M = {}; M.A = function () { return 1; };'
        ' function h(M) { A.X = 5; } h(0); return M.A(); } function g() { return A.X; }'
        ' A.X = 0; var before = g(); f(); var after = g(); try { use(A); } catch (e) {}'
        ' console.log(before, after);'
    ),
    'an outer namespace the batch flattens': (
        'var A = {}; function f() { var M = {}; M.A = function () { return 1; };'
        ' function h(M) { A.X = 5; } h(0); return M.A(); } function g() { return A.X; }'
        ' A.X = 0; var before = g(); f(); var after = g(); console.log(before, after);'
    ),
}

A_PROPERTY_READ_BELOW_A_BINDING_OF_ITS_OWN_NAME = {
    'nested var': (
        'var NS = {}; NS.p = 2; function f() { var p = 1; return NS.p; } console.log(f());'
    ),
    'nested parameter': (
        'var NS = {}; NS.p = 2; function f(p) { return NS.p; } console.log(f(1));'
    ),
    'inner namespace': (
        'var NS = {}; NS.p = 2;'
        ' function f() { var NS2 = {}; NS2.p = 1; return NS.p; } console.log(f());'
    ),
}

A_KEY_A_BARE_NAME_CANNOT_CARRY = [
    'function f(q) { var NS = {}; NS["foo-bar"] = q; return NS["foo-bar"]; }'
    ' console.log(f(Math.random() < 2 ? 1 : 0));',
    'function f(q) { var NS = {}; NS.if = q; return NS.if + 1; }'
    ' console.log(f(Math.random() < 2 ? 1 : 0));',
    'function f(q) { var NS = {}; NS.default = function () { return q; }; return NS.default(); }'
    ' console.log(f(Math.random() < 2 ? 1 : 0));',
    'function f(o) { var NS = {}; NS.x = 1; with (o) { console.log(NS.x); } } f({ x: 2 });',
    'function f(s) { var NS = {}; NS.x = 1; eval(s); console.log(NS.x); } f("x = 2");',
    'var NS = {}; NS.k = 1; function inner(s) { eval(s); return NS.k; } NS.k = 2;'
    ' console.log(inner("var k = 3"));',
]


A_NAMESPACE_MADE_WHERE_NOT_EVERY_ACCESS_REACHES_IT = {
    'made in a loop': (
        'function f(n) { var NS, seen = []; for (var i = 0; i < n; i++) {'
        ' NS = {}; seen.push(NS.a); NS.a = i; } return seen.join(); } console.log(f(3));'
    ),
    'read before it is made': (
        'function f() { var NS; function g() { return NS.a; }'
        ' try { g(); } catch (e) { console.log(e.name); } NS = {}; NS.a = 1; return g(); }'
        ' console.log(f());'
    ),
    'made twice': (
        'function f() { var NS; NS = {}; NS.a = 1; var g = function () { return NS.a; };'
        ' NS = {}; return g(); } console.log(f());'
    ),
    'made by a nested function': (
        'function f() { var NS; function make() { NS = {}; } make(); NS.a = 1; make(); return NS.a; }'
        ' console.log(f());'
    ),
}


class TestNamespaceFlattening(TestJsDeobfuscator):

    def _flatten(self, source: str) -> str:
        return self._run_transformer(source, JsNamespaceFlattening)

    def _flatten_one_plan_at_a_time(self, source: str) -> str:
        ast = JsParser(source).parse()
        instance = JsNamespaceFlattening()
        instance.options = None
        instance.batching = False
        instance.visit(ast)
        return JsSynthesizer().convert(ast)

    def test_basic_namespace_flatten(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x, y;
                x = 1;
                y = x + 2;
                """
            ),
            self._flatten('var NS = {}; NS.x = 1; NS.y = NS.x + 2;'),
        )

    def test_computed_string_access(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x, y;
                x = 1;
                y = x;
                """
            ),
            self._flatten('var NS = {}; NS["x"] = 1; NS["y"] = NS["x"];'),
        )

    def test_reject_bare_reference(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var NS = {};
                NS.x = 1;
                f(NS);
                """
            ),
            self._flatten('var NS = {}; NS.x = 1; f(NS);'),
        )

    def test_reject_computed_dynamic_key(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var NS = {};
                NS[key] = 1;
                """
            ),
            self._flatten('var NS = {}; NS[key] = 1;'),
        )

    def test_conflict_skips_conflicting_property(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var y;
                var NS = {};
                NS.x = 1;
                y = 2;
                var x = 10;
                """
            ),
            self._flatten('var NS = {}; NS.x = 1; NS.y = 2; var x = 10;'),
        )

    def test_shadowing_nested_function_untouched(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var a;
                a = 1;
                function f() {
                  var NS;
                  return NS.b;
                }
                """
            ),
            self._flatten('var NS = {}; NS.a = 1; function f() { var NS; return NS.b; }'),
        )

    def test_non_shadowing_nested_function_rewritten(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x;
                x = 1;
                function f() {
                  return x;
                }
                """
            ),
            self._flatten('var NS = {}; NS.x = 1; function f() { return NS.x; }'),
        )

    def test_block_scoped_shadow_does_not_block_flatten(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x;
                x = 1;
                {
                  let x = 9;
                  log(x);
                }
                log(x);
                """
            ),
            self._flatten('var NS = {}; NS.x = 1; { let x = 9; log(x); } log(NS.x);'),
        )

    def test_destructured_param_shadow_does_not_block_flatten(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x;
                x = 1;
                function g([x]) {
                  return x;
                }
                log(x + g([2]));
                """
            ),
            self._flatten('var NS = {}; NS.x = 1; function g([x]) { return x; } log(NS.x + g([2]));'),
        )

    def test_catch_param_shadow_does_not_block_flatten(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x;
                x = 1;
                try {
                  h();
                } catch (x) {
                  log(x);
                }
                log(x);
                """
            ),
            self._flatten('var NS = {}; NS.x = 1; try { h(); } catch (x) { log(x); } log(NS.x);'),
        )

    def test_function_hoisted_when_assignment_precedes_every_use(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function greet() {
                  return 42;
                }
                foo(greet);
                """
            ),
            self._flatten('var NS = {}; NS.greet = function () { return 42; }; foo(NS.greet);'),
        )

    def test_function_kept_in_place_when_a_use_can_run_before_assignment(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var greet;
                function early() {
                  return greet;
                }
                var probe = early();
                greet = function() {
                  return 42;
                };
                """
            ),
            self._flatten(
                'var NS = {}; function early() { return NS.greet; } var probe = early();'
                ' NS.greet = function () { return 42; };'),
        )

    def test_computed_read_before_assignment_keeps_function_in_place(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var greet;
                function early() {
                  return greet;
                }
                var probe = early();
                greet = function() {
                  return 42;
                };
                """
            ),
            self._flatten(
                'var NS = {}; function early() { return NS["greet"]; } var probe = early();'
                ' NS.greet = function () { return 42; };'),
        )

    def test_object_property_init_kept_in_place(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var config;
                config = {};
                config.x = 1;
                """
            ),
            self._flatten('var NS = {}; NS.config = {}; NS.config.x = 1;'),
        )

    def test_named_function_expression_kept_in_place(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var f;
                f = function fact(n) {
                  return n;
                };
                foo(f);
                """
            ),
            self._flatten('var NS = {}; NS.f = function fact(n) { return n; }; foo(NS.f);'),
        )

    def test_deleted_property_blocks_flattening(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var NS = {};
                NS.x = 1;
                delete NS.x;
                """
            ),
            self._flatten('var NS = {}; NS.x = 1; delete NS.x;'),
        )

    def test_a_namespace_whose_method_reads_it_through_this_stays_whole(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var NS = {};
                NS.x = 5;
                NS.f = function() {
                  return this.x;
                };
                log(NS.f());
                """
            ),
            self._flatten('var NS = {}; NS.x = 5; NS.f = function () { return this.x; }; log(NS.f());'),
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_a_method_reading_its_namespace_through_this_still_reads_it(self):
        for source in [
            'var NS = {}; NS.x = 5; NS.f = function () { return this.x; }; console.log(NS.f());',
            'var NS = {}; NS.x = 5; NS.f = function () { return (() => this.x)(); }; console.log(NS.f());',
            'var NS = {}; NS.x = 5; NS.f = function () { return this; }; console.log(NS.f().x);',
            'var NS = {}; NS.x = 5; NS.g = function () { return this.x; }; NS.f = NS.g; console.log(NS.f());',
        ]:
            with self.subTest(source):
                self.assertEqual(behavior(self._flatten(source)), ('5\n', None))
                self.assertEqual(before_and_after(source), (('5\n', None), ('5\n', None)))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_a_method_stored_other_than_by_a_plain_assignment_still_reads_its_namespace(self):
        for store in [
            '[NS.f] = [function () { return this.x; }];',
            '({ a: NS.f } = { a: function () { return this.x; } });',
            'for (NS.f of [function () { return this.x; }]);',
            '(NS.f) = function () { return this.x; };',
        ]:
            source = (
                '(function () { var NS = {}; NS.x = 5; NS.f = function () { return 1; };'
                F' {store} console.log(NS.f()); }})();'
            )
            with self.subTest(store):
                self.assertEqual(behavior(self._flatten(source)), ('5\n', None))
                self.assertEqual(before_and_after(source), (('5\n', None), ('5\n', None)))

    def test_this_method_called_through_sequence_in_a_function_is_flattened(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function main() {
                  function f() {
                    return this.x;
                  }
                  var x;
                  x = 5;
                  log((0, f)());
                }
                """
            ),
            self._flatten(
                'function main() { var NS = {}; NS.x = 5; NS.f = function () { return this.x; };'
                ' log((0, NS.f)()); }'
            ),
        )

    def test_this_method_called_through_alias_in_a_function_is_flattened(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function main() {
                  function f() {
                    return this.x;
                  }
                  var x;
                  x = 5;
                  var g = f;
                  log(g());
                }
                """
            ),
            self._flatten(
                'function main() { var NS = {}; NS.x = 5; NS.f = function () { return this.x; };'
                ' var g = NS.f; log(g()); }'
            ),
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    @backlog
    def test_a_this_method_called_detached_at_the_top_level_still_reads_the_global_object(self):
        for call in [
            'console.log((0, NS.f)());',
            'var g = NS.f; console.log(g());',
        ]:
            source = F'var NS = {{}}; NS.x = 5; NS.f = function () {{ return this.x; }}; {call}'
            with self.subTest(call):
                self.assertEqual(before_and_after_in_a_host(source), (prints('undefined'), prints('undefined')))

    def test_this_free_method_receiver_called_is_flattened(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  return 1;
                }
                log(f());
                """
            ),
            self._flatten('var NS = {}; NS.f = function () { return 1; }; log(NS.f());'),
        )

    def test_this_method_called_through_parentheses_kept_on_namespace(self):
        source = 'var NS = {}; NS.f = function () { return this.x; }; log((NS.f)());'
        self.assertEqual(self._run_transformers(source), self._flatten(source))

    def test_this_method_constructed_with_new_is_flattened(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  return this;
                }
                new f();
                """
            ),
            self._flatten('var NS = {}; NS.f = function () { return this; }; new NS.f();'),
        )

    def test_opaque_value_receiver_called_kept_on_namespace(self):
        source = 'var NS = {}; NS.f = impl(); NS.f();'
        self.assertEqual(self._run_transformers(source), self._flatten(source))

    def test_the_declarations_a_flattening_writes_stand_behind_the_directive(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function f(a) {
                  'use strict';
                  var p;
                  p = a;
                  return p;
                }
                f(1);
                """
            ),
            self._flatten(
                "function f(a) { 'use strict'; var NS = {}; NS.p = a; return NS.p; }\nf(1);"),
        )

    def test_the_same_declarations_stand_behind_a_scripts_directive(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                'use strict';
                var p;
                p = 1;
                console.log(p);
                """
            ),
            self._flatten("'use strict';\nvar NS = {};\nNS.p = 1;\nconsole.log(NS.p);"),
        )

    def test_property_held_back_when_member_object_reads_the_name(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var k = { y: 7 };
                function f() {
                  var NS = {};
                  NS.k = 1;
                  return k.y;
                }
                """
            ),
            self._flatten(
                'var k = {y: 7}; function f() { var NS = {}; NS.k = 1; return k.y; }'),
        )

    def test_hoist_held_back_when_declaration_name_captures_the_bodies_free_name(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var NS = {};
                NS.g = function() {
                  return g.y;
                };
                foo(NS.g);
                """
            ),
            self._flatten('var NS = {}; NS.g = function () { return g.y; }; foo(NS.g);'),
        )

    def test_two_declarators_of_one_namespace_name_are_left_alone(self):
        source = (
            'var NS = {}; NS.g = function () { return 42; };'
            ' var NS = {}; NS.g = function () { return 7; }; foo(NS.g);'
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                var NS = {};
                NS.g = function() {
                  return 42;
                };
                var NS = {};
                NS.g = function() {
                  return 7;
                };
                foo(NS.g);
                """
            ),
            self._flatten(source),
        )
        self.assertEqual(self._flatten(source), self._flatten_one_plan_at_a_time(source))

    def test_a_batch_holds_back_a_key_an_earlier_plan_emits(self):
        source = (
            'var A = {}; var B = {}; A.k = 1; A.j = 2; B.k = 3; B.m = 4;'
            ' log(A.k + A.j + B.k + B.m);'
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                var m;
                var j, k;
                var B = {};
                k = 1;
                j = 2;
                B.k = 3;
                m = 4;
                log(k + j + B.k + m);
                """
            ),
            self._flatten(source),
        )
        self.assertEqual(self._flatten(source), self._flatten_one_plan_at_a_time(source))

    @opportunity
    def test_a_namespace_declared_with_properties_flattens_like_an_empty_one(self):
        self.assertEqual(
            'SINK(1, 6);',
            self._deobfuscate('var X = {a: 1}; X.Y = [5, 6]; SINK(X.a, X.Y[1]);'),
        )

    def test_a_namespace_declared_bare_and_made_once_in_a_block_flattens(self):
        source = inspect.cleandoc(
            """
            function f(c) {
              var NS;
              if (c) {
                NS = {};
                NS.a = c;
                NS.g = function () { return NS.a + 1; };
                return NS.g();
              }
              return 0;
            }
            console.log(f(process.argv[2] ? 0 : 5));
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function f(c) {
                  var a, g;
                  if (c) {
                    a = c;
                    g = function() {
                      return a + 1;
                    };
                    return g();
                  }
                  return 0;
                }
                console.log(f(process.argv[2] ? 0 : 5));
                """
            ),
            self._flatten(source),
        )
        self.assertEqual(self._flatten(source), self._flatten_one_plan_at_a_time(source))

    def test_a_namespace_made_where_not_every_access_reaches_it_stays(self):
        for label, source in A_NAMESPACE_MADE_WHERE_NOT_EVERY_ACCESS_REACHES_IT.items():
            with self.subTest(label):
                self.assertEqual(self._flatten(source), JsSynthesizer().convert(JsParser(source).parse()))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_a_namespace_made_where_not_every_access_reaches_it_still_prints_it(self):
        for label, source in A_NAMESPACE_MADE_WHERE_NOT_EVERY_ACCESS_REACHES_IT.items():
            with self.subTest(label):
                self.assertEqual(behavior(source), behavior(self._flatten(source)))
                self.assertEqual(*before_and_after(source))

    def test_a_namespace_whose_object_a_labelled_statement_makes_stays_or_flattens_dropping_the_label(self):
        source = (
            "'use strict'; function f(c) { var NS; made: NS = {}; NS.a = c + 1; return NS.a; }"
            ' console.log(f(1));'
        )
        flattened = inspect.cleandoc(
            """
            'use strict';
            function f(c) {
              var a;
              a = c + 1;
              return a;
            }
            console.log(f(1));
            """
        )
        self.assertIn(self._flatten(source), (JsSynthesizer().convert(JsParser(source).parse()), flattened))

    def test_two_namespaces_declared_in_one_statement_flatten_together(self):
        source = 'var A = {}, B = {}; A.x = 1; B.y = 2; log(A.x + B.y);'
        self.assertEqual(
            inspect.cleandoc(
                """
                var y;
                var x;
                x = 1;
                y = 2;
                log(x + y);
                """
            ),
            self._flatten(source),
        )
        self.assertEqual(self._flatten(source), self._flatten_one_plan_at_a_time(source))

    def test_two_namespaces_declared_in_one_statement_hoist_together(self):
        source = (
            'var A = {}, B = {}; A.f = function () { return 1; };'
            ' B.g = function () { return 2; }; log(A.f() + B.g());'
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function g() {
                  return 2;
                }
                function f() {
                  return 1;
                }
                log(f() + g());
                """
            ),
            self._flatten(source),
        )
        self.assertEqual(self._flatten(source), self._flatten_one_plan_at_a_time(source))

    def test_two_hoists_in_one_batch_splice_by_statement_not_position(self):
        source = (
            'var A = {}; var B = {}; A.f = function () { return 1; };'
            ' B.g = function () { return 2; }; foo(A.f, B.g);'
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function g() {
                  return 2;
                }
                function f() {
                  return 1;
                }
                foo(f, g);
                """
            ),
            self._flatten(source),
        )
        self.assertEqual(self._flatten(source), self._flatten_one_plan_at_a_time(source))

    def test_a_read_below_a_binding_of_its_name_flattens_the_same_way_one_plan_at_a_time(self):
        for source in [
            *A_READ_INSIDE_A_FUNCTION_BINDING_THE_NAMESPACES_NAME.values(),
            *A_PROPERTY_READ_BELOW_A_BINDING_OF_ITS_OWN_NAME.values(),
        ]:
            with self.subTest(source):
                self.assertEqual(self._flatten(source), self._flatten_one_plan_at_a_time(source))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_a_read_below_a_binding_of_its_name_still_reads_the_namespace(self):
        for source in [
            *A_READ_INSIDE_A_FUNCTION_BINDING_THE_NAMESPACES_NAME.values(),
            *A_PROPERTY_READ_BELOW_A_BINDING_OF_ITS_OWN_NAME.values(),
        ]:
            with self.subTest(source):
                self.assertEqual(behavior(source), behavior(self._flatten(source)))
                self.assertEqual(*before_and_after(source))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_a_key_a_bare_name_cannot_carry_still_prints_what_it_printed(self):
        for source in A_KEY_A_BARE_NAME_CANNOT_CARRY:
            with self.subTest(source):
                self.assertEqual(behavior(source), behavior(self._flatten(source)))
                self.assertEqual(*before_and_after(source))

    def test_a_key_a_pattern_names_under_every_suffix_stays_on_the_namespace(self):
        source = 'var cfg = {};\ncfg.main = 1;\nprint(cfg.main);'
        self.assertEqual(
            source,
            self._run_transformer(
                source, JsNamespaceFlattening, DeobfuscationOptions(entrypoints=('m*',))))
