from __future__ import annotations

import inspect
import unittest

from test import a_property_of_the_batch_itself
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator

from refinery.lib.scripts.js.deobfuscation.namespaces import JsNamespaceFlattening
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer

#: Programs reading a namespace property from inside a function that binds the namespace's own name,
#: so the conflict walk prunes the subtree the read stands in and the flattening hoists the key over
#: the read. The outer namespace of one row is kept by a bare read and the other's flattens. Held by
#: `test.lib.scripts.js.test_unfixed_defects.TestAReadBelowAHoistTheConflictWalkNeverSaw` and by the
#: parity row of this module.
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

#: Programs reading a namespace property from below a binding of the property's own name, so a
#: flattening that rewrites the read to a bare identifier would rebind it. Held by
#: `test.lib.scripts.js.test_unfixed_defects.TestAPropertyReadBelowABindingOfItsOwnName`.
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


class TestNamespaceFlattening(TestJsDeobfuscator):

    def _flatten(self, source: str) -> str:
        return self._run_transformer(source, JsNamespaceFlattening)

    def _flatten_one_plan_at_a_time(self, source: str) -> str:
        """
        The pass's sequential self: each decided plan applies at the moment it is decided, against
        the tree the previous plans already changed. Its output must equal the batched run's.
        """
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
        """
        `early()` reads the property and runs before the assignment, so a hoisted `function greet(){}`
        would let that call see the function early; the assignment stays in place behind a bare `var`.
        """
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
        """
        Hoisting to `function f(){}` would drop the expression's own name `fact`, leaving the
        recursive call unbound; the in-place form preserves it.
        """
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
        """
        `delete p` on a bare `var` binding is not a property removal, so a namespace with a deleted
        property is left intact.
        """
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

    def test_this_method_receiver_called_kept_on_namespace(self):
        """
        `NS.f()` binds `this === NS`; flattening to `f()` would rebind `this` to the global object, so
        a `this`-observing method that is receiver-called stays on the namespace. Sibling data
        properties still flatten around it.
        """
        self.assertEqual(
            inspect.cleandoc(
                """
                var x;
                var NS = {};
                x = 5;
                NS.f = function() {
                  return this.x;
                };
                log(NS.f());
                """
            ),
            self._flatten('var NS = {}; NS.x = 5; NS.f = function () { return this.x; }; log(NS.f());'),
        )

    def test_this_method_called_through_sequence_is_flattened(self):
        """
        `(0, NS.f)()` detaches the receiver, so `this` is the global object in both forms and the
        `this`-observing method flattens.
        """
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  return this.x;
                }
                var x;
                x = 5;
                log((0, f)());
                """
            ),
            self._flatten('var NS = {}; NS.x = 5; NS.f = function () { return this.x; }; log((0, NS.f)());'),
        )

    def test_this_method_called_through_alias_is_flattened(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  return this.x;
                }
                var x;
                x = 5;
                var g = f;
                log(g());
                """
            ),
            self._flatten(
                'var NS = {}; NS.x = 5; NS.f = function () { return this.x; }; var g = NS.f; log(g());'),
        )

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
        """
        Parentheses are transparent to the receiver: `(NS.f)()` still binds `this === NS`, so the
        method is held back unchanged.
        """
        source = 'var NS = {}; NS.f = function () { return this.x; }; log((NS.f)());'
        self.assertEqual(self._run_transformers(source), self._flatten(source))

    def test_this_method_constructed_with_new_is_flattened(self):
        """
        `new NS.f()` gives the constructor a fresh `this`, so detaching the callee does not change it.
        """
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
        """
        The value of `NS.f` is not a provable `this`-free function literal, so a receiver call on it is
        held back rather than detached.
        """
        source = 'var NS = {}; NS.f = impl(); NS.f();'
        self.assertEqual(self._run_transformers(source), self._flatten(source))

    def test_the_declarations_a_flattening_writes_stand_behind_the_directive(self):
        """
        Flattening a namespace object writes a declaration for every bare name it leaves behind, and
        that declaration goes below the `'use strict'` the body opens with. Written above it, the
        directive would stop being one and the body would run sloppy.
        """
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
        """
        A use of the flattened name in object position (`k.y`) is captured by the emitted
        `var k` the same way a bare use is, so the property stays on the namespace.
        """
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
        """
        Raising `NS.g = function () { return g.y; }` to a hoisted `function g(){}` would rebind the
        `g` the body reads to the declaration itself, so the assignment stays in place behind the
        namespace object.
        """
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
        """
        The second declarator's own identifier is a bare reference to the name, so neither declaration
        describes a namespace whose every reference is a property access, and the pass dissolves
        neither. The batch decides both candidates against one tree and refuses both the same way.
        """
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
        """
        `A` and `B` flatten in one batch and both carry the name `k`. The plan for `A` emits
        `var k`, so the plan for `B` must leave its `B.k` on the namespace rather than rewriting the
        reads into the binding `A` owns; the sequential self refuses the key by the rebuilt model
        and the two runs agree.
        """
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

    def test_two_hoists_in_one_batch_splice_by_statement_not_position(self):
        """
        Both plans hoist a function declaration into the same body, and applying the first inserts
        statements the second's recorded positions would no longer point at. The splices carry the
        assignment statements themselves, so the second plan still finds its own and both runs agree.
        """
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

    @a_property_of_the_batch_itself
    @unittest.expectedFailure
    def test_a_hoist_a_pruned_conflict_walk_allows_flattens_the_same_way_one_plan_at_a_time(self):
        """
        The inner plan's conflict walk prunes `h` for binding the namespace's name `M`, so it never
        sees the `A` in `A.X = 5` and hoists `function A` over the read. The batched pass flattens
        the outer namespace too and rewrites the read out from under the hoist; the sequential self
        declines the outer plan against the tree the inner plan already edited and leaves the capture
        standing, so the two outputs disagree. The ledger entry
        `test.lib.scripts.js.test_unfixed_defects.TestAReadBelowAHoistTheConflictWalkNeverSaw`
        holds the defect.
        """
        source = A_READ_INSIDE_A_FUNCTION_BINDING_THE_NAMESPACES_NAME[
            'an outer namespace the batch flattens'
        ]
        self.assertEqual(self._flatten(source), self._flatten_one_plan_at_a_time(source))
