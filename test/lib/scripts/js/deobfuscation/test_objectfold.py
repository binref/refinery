from __future__ import annotations

import inspect
import unittest

from test.lib.scripts.js.analysis.differential import node_executable
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator
from test.lib.scripts.js.ledger import (
    before_and_after,
    each_program_still_prints,
)


class TestObjectFold(TestJsDeobfuscator):

    def test_string_property_inlined(self):
        self.assertEqual(
            "x('hello');",
            self._objectfold("var o = {'k': 'hello'}; x(o['k']);"),
        )

    def test_function_wrapper_inlined(self):
        self.assertEqual(
            'var r = 1 + 2;',
            self._objectfold("var o = {'f': function(a, b) { return a + b; }}; var r = o['f'](1, 2);"),
        )

    def test_side_effecting_property_value_not_folded(self):
        source = inspect.cleandoc(
            """
            var o = { a: 1, b: f() };
            console.log(o.a);
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_object_member_mutated_through_with_not_folded(self):
        source = inspect.cleandoc(
            """
            var o = { p: 1 };
            with (q) {
              o.p = 2;
            }
            SINK(o.p);
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_global_alias_member_read_keeps_object_and_is_not_folded(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var o = { p: 1 };
                SINK(1);
                dump(globalThis.o.p);
                """
            ),
            self._objectfold('var o = { p: 1 }; SINK(o.p); dump(globalThis.o.p);'),
        )

    def test_object_folded_when_with_does_not_name_it(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                with (q) {
                  z = 2;
                }
                SINK(1);
                """
            ),
            self._objectfold('var o = { p: 1 }; with (q) { z = 2; } SINK(o.p);'),
        )

    def test_local_object_in_function_with_direct_eval_not_folded(self):
        source = inspect.cleandoc(
            """
            function f() {
              var o = { p: 1 };
              eval("x");
              SINK(o.p);
            }
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_script_scope_object_still_folds_under_direct_eval_residual(self):
        """
        A script-scope object folds even though the program has a direct `eval` that could name it:
        freezing every global on an opaque surface would regress real samples (the b91 lookup arrays), so
        this is the accepted dynamic-scope residual, not a bug.
        """
        self.assertEqual(
            inspect.cleandoc(
                """
                eval("x");
                SINK(1);
                """
            ),
            self._objectfold('var o = { p: 1 }; eval("x"); SINK(o.p);'),
        )

    def test_object_value_reassigned_through_with_not_folded(self):
        source = inspect.cleandoc(
            """
            var x = 1;
            var o = { p: x };
            with (q) {
              x = 2;
            }
            SINK(o.p);
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_object_value_reassignable_by_direct_eval_not_folded(self):
        """
        The value binding `x` is reassignable by the direct `eval` in `outer`, while the object `o`
        lives in `inner`, where its own container is immutable. Only the value-stability gate can
        block this fold.
        """
        source = inspect.cleandoc(
            """
            function outer() {
              var x = 1;
              eval("x = 2");
              function inner() {
                var o = { p: x };
                SINK(o.p);
              }
              inner();
            }
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_object_value_binding_not_named_by_with_still_folds(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x = 1;
                with (q) {
                  z = 2;
                }
                SINK(x);
                """
            ),
            self._objectfold('var x = 1; var o = { p: x }; with (q) { z = 2; } SINK(o.p);'),
        )

    def test_object_read_through_with_folds_resolved_access_but_keeps_declaration(self):
        """
        The `with` body reads `o.p` without mutating it, so the container stays immutable and the resolved
        `SINK(o.p)` folds to the value. The declaration must be kept: the `with`-body `o.p` still names
        `o` (it denotes this object when `q` lacks the property), and removing `var o` would leave that
        reference dangling.
        """
        self.assertEqual(
            inspect.cleandoc(
                """
                var o = { p: 1 };
                with (q) {
                  y = o.p;
                }
                SINK(1);
                """
            ),
            self._objectfold('var o = { p: 1 }; with (q) { y = o.p; } SINK(o.p);'),
        )

    def test_proto_setting_object_not_folded(self):
        source = inspect.cleandoc(
            """
            var o = { __proto__: base, a: 1 };
            SINK(o.__proto__);
            SINK(o.a);
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_this_method_not_folded(self):
        source = inspect.cleandoc(
            """
            var o = { 'k': 'AB', 'f': function(i) {
              return this.k.charAt(i);
            } };
            var r = o['f'](0);
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_super_method_not_folded(self):
        source = inspect.cleandoc(
            """
            var o = { m() {
              return super.toString();
            } };
            SINK(o.m());
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_async_method_call_keeps_async_wrapper(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var p = async function() {
                  return 1;
                }();
                """
            ),
            self._objectfold('var o = { async m() { return 1; } }; var p = o.m();'),
        )

    def test_generator_method_call_keeps_generator_wrapper(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var p = function*() {
                  return 1;
                }();
                """
            ),
            self._objectfold('var o = { *m() { return 1; } }; var p = o.m();'),
        )

    def test_method_forwarding_eval_into_a_callee_stays_indirect(self):
        self.assertEqual(
            "(0, eval)('code');",
            self._objectfold("var o = { m: function (x) { return x; } }; o.m(eval)('code');"),
        )

    def test_method_forwarding_eval_into_a_read_stays_bare(self):
        self.assertEqual(
            'typeof eval;',
            self._objectfold('var o = { m: function (x) { return x; } }; typeof o.m(eval);'),
        )

    def test_regex_valued_property_not_folded(self):
        source = inspect.cleandoc(
            """
            var o = { p: /abc/ };
            SINK(o.p === o.p);
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_this_in_nested_function_still_folds(self):
        source = inspect.cleandoc(
            """
            var o = {'f': function(a) { return g(a, function() { return this.x; }); }};
            var r = o['f'](1);
            """
        )
        result = self._objectfold(source)
        self.assertEqual(
            inspect.cleandoc(
                """
                var r = function(a) {
                  return g(a, function() {
                    return this.x;
                  });
                }(1);
                """
            ),
            result,
        )

    def test_this_in_nested_arrow_not_folded(self):
        source = inspect.cleandoc(
            """
            var o = { 'k': 'AB', 'f': function(i) {
              return (() => this.k.charAt(i))();
            } };
            var r = o['f'](0);
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_arrow_property_using_this_not_folded(self):
        source = inspect.cleandoc(
            """
            var o = { 'f': () => this.x };
            function h() {
              return o['f']();
            }
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_class_super_class_using_this_not_folded(self):
        source = inspect.cleandoc(
            """
            var o = { 'f': function() {
              return class extends this.Base {};
            } };
            var r = o['f']();
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_class_computed_key_using_this_not_folded(self):
        source = inspect.cleandoc(
            """
            var o = { 'k': 'm', 'f': function() {
              return class {
                [this.k]() {}
              };
            } };
            var r = o['f']();
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_class_method_body_this_still_folds(self):
        source = inspect.cleandoc(
            """
            var o = {'f': function() { return class { m() { return this.x; } }; }};
            var r = o['f']();
            """
        )
        result = self._objectfold(source)
        self.assertEqual(
            inspect.cleandoc(
                """
                var r = function() {
                  return class {
                    m() {
                      return this.x;
                    }
                  };
                }();
                """
            ),
            result,
        )

    def test_arrow_value_folded_into_callee_is_parenthesized(self):
        source = "var o = {'f': () => g()}; var r = o['f']();"
        self.assertEqual(self._objectfold(source), 'var r = (() => g())();')

    def test_mutated_object_unchanged(self):
        source = inspect.cleandoc(
            """
            var o = { 'k': 'hello' };
            o = other;
            x(o['k']);
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_non_literal_key_unchanged(self):
        source = inspect.cleandoc(
            """
            var o = { [expr]: 'hello' };
            x(o[expr]);
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_multiple_properties(self):
        source = inspect.cleandoc(
            """
            var o = {'a': 'hello', 'b': ', ', 'c': function(x, y) { return x + y; }};
            var r = o['c'](o['a'], o['b']);
            """
        )
        self.assertEqual(
            "var r = 'hello' + ', ';",
            self._objectfold(source),
        )

    def test_object_with_method_kind_skipped(self):
        self.assertEqual("'hello';", self._objectfold("var o = {'k': 'hello'}; o.k;"))

    def test_generated_medium_object_fold(self):
        result = self._objectfold(
            r"function classify(_0xc9c876){var _0x159b71={'QUMXw':function(_0x794a00,_0x30c617){return _0x794a00<_"
            r"0x30c617;},'smFRR':function(_0x56d1ff,_0x5094f9){return _0x56d1ff>_0x5094f9;},'KVVfA':'positive','nQ"
            r"fTZ':function(_0x50e61b,_0x19cfc3){return _0x50e61b<_0x19cfc3;},'YFNps':'negative','uvdVt':'zero'};v"
            r"ar _0xc3dbcf=[];for(var _0x254ae8=0x0;_0x159b71['QUMXw'](_0x254ae8,_0xc9c876['length']);_0x254ae8++)"
            r"{var _0xe54f7c=_0xc9c876[_0x254ae8];if(_0x159b71['smFRR'](_0xe54f7c,0x0)){_0xc3dbcf['push'](_0x159b7"
            r"1['KVVfA']);}else if(_0x159b71['nQfTZ'](_0xe54f7c,0x0)){_0xc3dbcf['push'](_0x159b71['YFNps']);}else{"
            r"_0xc3dbcf['push'](_0x159b71['uvdVt']);}}var _0x51ec37=_0xc3dbcf['length'];return{'items':_0xc3dbcf,'"
            r"total':_0x51ec37};}"
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function classify(_0xc9c876) {
                  var _0xc3dbcf = [];
                  for (var _0x254ae8 = 0x0; _0x254ae8 < _0xc9c876['length']; _0x254ae8++) {
                    var _0xe54f7c = _0xc9c876[_0x254ae8];
                    if (_0xe54f7c > 0x0) {
                      _0xc3dbcf['push']('positive');
                    } else {
                      if (_0xe54f7c < 0x0) {
                        _0xc3dbcf['push']('negative');
                      } else {
                        _0xc3dbcf['push']('zero');
                      }
                    }
                  }
                  var _0x51ec37 = _0xc3dbcf['length'];
                  return { 'items': _0xc3dbcf, 'total': _0x51ec37 };
                }
                """
            ),
            result,
        )

    def test_multi_declarator(self):
        source = "var x = 1, o = {'k': 'hello'}, y = 2; z(o['k']);"
        self.assertEqual(
            inspect.cleandoc(
                """
                var x = 1, y = 2;
                z('hello');
                """
            ),
            self._objectfold(source),
        )

    def test_partial_key_coverage(self):
        source = "var o = {'a': 'hello', 'b': 'world'}; x(o['a']); y(o['missing']);"
        self.assertEqual(
            inspect.cleandoc(
                """
                x('hello');
                y(void 0);
                """
            ),
            self._objectfold(source),
        )

    def test_absent_non_inherited_key_folds_to_undefined(self):
        self.assertEqual('SINK(void 0);', self._objectfold('var o = { a: 1 }; SINK(o.b);'))

    def test_inherited_member_access_not_folded(self):
        source = inspect.cleandoc(
            """
            var o = { a: 1 };
            SINK(o.toString());
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_self_referential_object_not_folded(self):
        source = inspect.cleandoc(
            """
            var o = { a: 1, f: function() {
              return o.a;
            } };
            SINK(o.f());
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_mutable_variable_property_value_not_folded(self):
        source = inspect.cleandoc(
            """
            function f(x) {
              var o = { p: x };
              x = 99;
              return o.p;
            }
            SINK(f(1));
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_global_alias_member_write_value_not_folded(self):
        source = inspect.cleandoc(
            """
            var o = { p: g };
            globalThis.g = 99;
            SINK(o.p);
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_global_alias_computed_member_write_value_not_folded(self):
        source = inspect.cleandoc(
            """
            var o = { p: g };
            globalThis['g'] = 99;
            SINK(o.p);
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_window_alias_member_write_value_not_folded(self):
        source = inspect.cleandoc(
            """
            var o = { p: g };
            window.g = 99;
            SINK(o.p);
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_free_global_property_value_still_folded(self):
        self.assertEqual(
            'SINK(encodeURIComponent);',
            self._objectfold('var o = { e: encodeURIComponent }; SINK(o.e);'),
        )

    def test_local_alias_member_write_does_not_block_fold(self):
        source = inspect.cleandoc(
            """
            function f() {
              var window = {};
              var o = { p: g };
              window.g = 99;
              return o.p;
            }
            """
        )
        expected = inspect.cleandoc(
            """
            function f() {
              var window = {};
              window.g = 99;
              return g;
            }
            """
        )
        self.assertEqual(expected, self._objectfold(source))

    def test_coercion_of_mutated_container_not_folded(self):
        source = inspect.cleandoc(
            """
            var arr = [1, 2];
            var o = { p: arr + '' };
            arr.push(9);
            SINK(o.p);
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_unary_coercion_of_mutated_container_not_folded(self):
        source = inspect.cleandoc(
            """
            var arr = [1, 2];
            var o = { p: +arr };
            arr.push(9);
            SINK(o.p);
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_coercion_of_container_mutated_by_callee_not_folded(self):
        source = inspect.cleandoc(
            """
            function m(z) {
              z.push(9);
            }
            var arr = [1, 2];
            var o = { p: arr + '' };
            m(arr);
            SINK(o.p);
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_primitive_coercion_still_folded(self):
        expected = inspect.cleandoc(
            """
            var x = 5;
            SINK(x + '');
            """
        )
        self.assertEqual(expected, self._objectfold("var x = 5; var o = { p: x + '' }; SINK(o.p);"))

    def test_identity_read_of_mutated_container_still_folded(self):
        source = inspect.cleandoc(
            """
            var arr = [1, 2];
            var o = { p: arr };
            arr.push(9);
            SINK(o.p);
            """
        )
        expected = inspect.cleandoc(
            """
            var arr = [1, 2];
            arr.push(9);
            SINK(arr);
            """
        )
        self.assertEqual(expected, self._objectfold(source))

    def test_coercion_of_unmutated_container_still_folded(self):
        source = inspect.cleandoc(
            """
            var arr = [1, 2];
            var o = { p: arr + '' };
            SINK(o.p);
            """
        )
        expected = inspect.cleandoc(
            """
            var arr = [1, 2];
            SINK(arr + '');
            """
        )
        self.assertEqual(expected, self._objectfold(source))

    def test_nested_property_method_mutation_not_folded(self):
        source = inspect.cleandoc(
            """
            var o = { arr: [1, 2] };
            o.arr.unshift(9);
            SINK(o.arr[0]);
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_object_escaping_to_nested_mutating_callee_not_folded(self):
        source = inspect.cleandoc(
            """
            function mut(x) {
              x.arr.unshift(9);
            }
            var o = { arr: [1, 2] };
            mut(o);
            SINK(o.arr[0]);
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_property_reading_mutated_array_element_not_folded(self):
        source = inspect.cleandoc(
            """
            var arr = [1, 2];
            var o = { p: arr[0] };
            arr[0] = 99;
            SINK(o.p);
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_identity_compared_container_property_not_folded(self):
        source = inspect.cleandoc(
            """
            var o = { arr: [1, 2] };
            SINK(o.arr === o.arr);
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_function_valued_property_read_by_identity_not_folded(self):
        source = inspect.cleandoc(
            """
            var o = { f: function() {
              return 1;
            } };
            SINK(o.f === o.f);
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_parenthesized_function_property_read_by_identity_not_folded(self):
        """
        A parenthesized function value is the same function as the bare form, so a bare identity read of
        it must not clone it into two distinct functions either: the paren is seen through so the
        identity guard keeps the fold from happening.
        """
        source = inspect.cleandoc(
            """
            var o = { f: (function() {
              return 1;
            }) };
            SINK(o.f === o.f);
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_parenthesized_function_property_call_inlined(self):
        self.assertEqual(
            'SINK(2 + 1);',
            self._objectfold('var o = { f: (function(a) { return a + 1; }) }; SINK(o.f(2));'),
        )

    def test_fresh_array_returning_call_value_not_folded(self):
        source = inspect.cleandoc(
            """
            function mk(v) {
              return [v];
            }
            var inp = get();
            var o = { p: mk(inp) };
            SINK(o.p === o.p);
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_fresh_object_returning_call_value_not_folded(self):
        source = inspect.cleandoc(
            """
            function mk(v) {
              return { v: v };
            }
            var inp = get();
            var o = { p: mk(inp) };
            var a = o.p;
            a.x = 1;
            SINK(o.p.x);
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_value_folded_into_shadowing_scope_not_folded(self):
        source = inspect.cleandoc(
            """
            function A() {
              const n = 'OUTER';
              var o = { p: n };
              return function B(n) {
                return o.p;
              };
            }
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_value_reading_arguments_folded_into_nested_function_not_folded(self):
        source = inspect.cleandoc(
            """
            function A() {
              var o = { p: arguments };
              return function B() {
                return o.p;
              };
            }
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_aliased_container_property_not_folded(self):
        source = inspect.cleandoc(
            """
            var o = { arr: [1, 2] };
            var b = o.arr;
            b.unshift(9);
            SINK(o.arr[0]);
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_argument_escaped_container_property_not_folded(self):
        source = inspect.cleandoc(
            """
            function mut(a) {
              a.unshift(9);
            }
            var o = { arr: [1, 2] };
            mut(o.arr);
            SINK(o.arr[0]);
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_dynamic_key_preserves_object(self):
        source = "var o = {'a': 'hello', 'b': 'world'}; x(o['a']); y(o[z]);"
        self.assertEqual(
            inspect.cleandoc(
                """
                var o = { 'a': 'hello', 'b': 'world' };
                x('hello');
                y(o[z]);
                """
            ),
            self._objectfold(source),
        )

    def test_shadowing_inner_binding_not_folded(self):
        source = inspect.cleandoc(
            """
            function W() {
              var o = { p: 1 };
              g(o.p);
              function inner() {
                var o = { p: 2 };
                f(o);
                g(o.p);
              }
            }
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function W() {
                  g(1);
                  function inner() {
                    var o = { p: 2 };
                    f(o);
                    g(o.p);
                  }
                }
                """
            ),
            self._objectfold(source),
        )

    def test_benign_alias_keeps_declaration(self):
        source = "var o = {k: 'X'}; var b = o; SINK(o.k); SINK(b.k);"
        self.assertEqual(
            inspect.cleandoc(
                """
                var o = { k: 'X' };
                var b = o;
                SINK('X');
                SINK(b.k);
                """
            ),
            self._objectfold(source),
        )

    def test_for_of_member_target_unchanged(self):
        source = inspect.cleandoc(
            """
            var o = { k: 1 };
            for (o.k of xs) {}
            SINK(o.k);
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_destructuring_member_target_unchanged(self):
        source = inspect.cleandoc(
            """
            var o = { k: 1 };
            [o.k] = [9];
            SINK(o.k);
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_destructuring_default_member_target_unchanged(self):
        source = inspect.cleandoc(
            """
            var o = { k: 1 };
            [o.k = 9] = xs;
            SINK(o.k);
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_contextual_keyword_as_parameter(self):
        source = "var o = {'f': function(as, at) { return as < at; }}; var r = o['f'](x, 3);"
        self.assertEqual('var r = x < 3;', self._objectfold(source))

    def test_parenthesized_member_write_unchanged(self):
        source = inspect.cleandoc(
            """
            var o = { k: 1 };
            (o.k) = 9;
            SINK(o.k);
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_parenthesized_rebind_unchanged(self):
        source = inspect.cleandoc(
            """
            var o = { k: 1 };
            (o) = newobj;
            SINK(o.k);
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_var_redeclaration_unchanged(self):
        source = inspect.cleandoc(
            """
            var o = { k: 1 };
            SINK(o.k);
            var o = other;
            SINK(o.k);
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_chained_object_properties_fold_consistently(self):
        source = 'var a = {x: 7}; var b = {y: a.x}; SINK(a.x); SINK(b.y);'
        self.assertEqual('SINK(7);\nSINK(7);', self._objectfold(source))


class TestRegressions(TestJsDeobfuscator):

    def test_objectfold_var_in_nested_block_not_removed(self):
        source = inspect.cleandoc(
            """
            function f() {
              if (true) {
                var o = { 'k': 'hello' };
                x(o['k']);
              }
              return o['k'];
            }
            """
        )
        self.assertEqual(source, self._objectfold(source))


class TestRegressionBugs(TestJsDeobfuscator):

    def test_objectfold_no_inline_sideeffect_argument(self):
        source = inspect.cleandoc(
            """
            var o = {fn: function(a) { return a + a; }};
            o.fn(g());
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                (function(a) {
                  return a + a;
                }(g()));
                """
            ),
            self._objectfold(source),
        )

    def test_objectfold_getter_not_folded(self):
        source = inspect.cleandoc(
            """
            var o = { get x() {
              return 1;
            } };
            o.x;
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_property_reading_lexical_in_dead_zone_not_folded(self):
        """
        `{ p: x }` reads `x` before its `let` declaration — its temporal dead zone, a `ReferenceError`
        at runtime — so folding `o.p` to `x` at the later access site would replace the throw with the
        declared value; the object is left unfolded.
        """
        source = inspect.cleandoc(
            """
            function f() {
              var o = { p: x };
              let x = 5;
              return o.p;
            }
            """
        )
        self.assertEqual(source, self._objectfold(source))

    def test_property_reading_lexical_established_first_still_folds(self):
        source = inspect.cleandoc(
            """
            function f() {
              let x = 5;
              var o = { p: x };
              return o.p;
            }
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  let x = 5;
                  return x;
                }
                """
            ),
            self._objectfold(source),
        )

    def test_deferred_read_of_lexical_in_nested_function_still_folds(self):
        """
        The property value reads `x` only inside a nested function, evaluated when `o.p()` is called —
        a site folding preserves — not eagerly at the literal, so the dead-zone gate does not apply and
        the wrapper still inlines at its call site.
        """
        source = inspect.cleandoc(
            """
            function f() {
              var o = { p: function () { return x; } };
              let x = 5;
              return o.p();
            }
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  let x = 5;
                  return function() {
                    return x;
                  }();
                }
                """
            ),
            self._objectfold(source),
        )


#: Each row maps a program probing one argument-evaluation-order edge case — a dropped, reordered,
#: duplicated, or conditionally-read effect, a nested-arrow live read, or a pure-call reorder — to
#: what Node prints for it. Where substitution would change that order the fold keeps the function
#: value called with its arguments standing where they were written; where an argument is read once,
#: unconditionally, in order, before the body's own effects, it is substituted.
AN_ARGUMENT_WHOSE_EFFECT_THE_FOLD_OWES = {
    'function g() { SIDE = 1; return 2; }'
    ' var o = { m: function (a) { return 7; } };'
    ' console.log(o.m(g()));'
    ' console.log(SIDE);': '7\n1\n',
    "var LOG = '';"
    " function p() { LOG += 'p'; return 1; }"
    " function q() { LOG += 'q'; return 2; }"
    ' var o = { m: function (a, b) { return b + a; } };'
    ' console.log(o.m(p(), q()), LOG);': '3 pq\n',
    "var LOG = '';"
    " function p() { LOG += 'p'; return 0; }"
    " function q() { LOG += 'q'; return 2; }"
    ' var o = { m: function (a, b) { return a ? b : 5; } };'
    ' console.log(o.m(p(), q()), LOG);': '5 pq\n',
    "var LOG = '';"
    " function g() { LOG += 'g'; return 5; }"
    ' var o = { m: function (a, a) { return a; } };'
    ' console.log(o.m(g(), 1), LOG);': '1 g\n',
    'var x = 1;'
    ' var o = { m: function (a, b) { return b + a; } };'
    ' console.log(o.m(x, x = 5));': '6\n',
    'var x = 1;'
    ' var o = { m: function (a, b) { return a + b + a; } };'
    ' console.log(o.m(x, x = 5));': '7\n',
    "var LOG = '';"
    " function e() { LOG += 'e'; return 'x'; }"
    ' var o = { m: function (a, b) { return a?.[b]; } };'
    ' console.log(o.m(null, e()), LOG);': 'undefined e\n',
    "var LOG = '';"
    " function f() { LOG += 'f'; return 1; }"
    " function g() { LOG += 'g'; return 2; }"
    ' var o = { m: function (a, b) { return a() + b; } };'
    ' console.log(o.m(f, g()), LOG);': '3 gf\n',
    'function g() { SIDE = 1; return 2; }'
    ' var o = { m: function (a) { return a + 7; } };'
    ' console.log(o.m(g()));'
    ' console.log(SIDE);': '9\n1\n',
    "var LOG = '';"
    " function p() { LOG += 'p'; return 1; }"
    " function q() { LOG += 'q'; return 2; }"
    ' var o = { m: function (a, b) { return a + b; } };'
    ' console.log(o.m(p(), q()), LOG);': '3 pq\n',
    "var LOG = '';"
    " function eff() { LOG += 'e'; return 5; }"
    ' var obj = { key: 1 };'
    ' var o = { m: function (a, k, b) { return a[k] ||= b; } };'
    " console.log(o.m(obj, 'key', eff()), LOG);": '1 e\n',
    'var x = 1;'
    ' var o = { m: function (a) { return () => a; } };'
    ' var f = o.m(x); x = 2;'
    ' console.log(f());': '1\n',
    'function p() { return 1; }'
    ' function q() { return 2; }'
    ' var o = { m: function (a, b) { return b + a; } };'
    ' console.log(o.m(p(), q()));': '3\n',
}


class TestAFoldedCallRunsItsArgumentsAsWritten(TestJsDeobfuscator):

    def test_an_argument_the_body_never_reads_still_runs(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                console.log(function(a) {
                  return 7;
                }(g()));
                """
            ),
            self._objectfold('var o = { m: function (a) { return 7; } }; console.log(o.m(g()));'),
        )

    def test_a_pair_the_body_reads_backwards_runs_in_written_order(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                console.log(function(a, b) {
                  return b + a;
                }(p(), q()));
                """
            ),
            self._objectfold(
                'var o = { m: function (a, b) { return b + a; } }; console.log(o.m(p(), q()));'
            ),
        )

    def test_an_argument_the_body_reads_conditionally_still_runs(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                console.log(function(a, b) {
                  return a ? b : 5;
                }(p(), q()));
                """
            ),
            self._objectfold(
                'var o = { m: function (a, b) { return a ? b : 5; } }; console.log(o.m(p(), q()));'
            ),
        )

    def test_an_argument_read_once_in_order_is_substituted(self):
        self.assertEqual(
            'console.log(g() + 7);',
            self._objectfold(
                'var o = { m: function (a) { return a + 7; } }; console.log(o.m(g()));'
            ),
        )

    def test_a_pair_read_in_declaration_order_is_substituted(self):
        self.assertEqual(
            'console.log(p() + q());',
            self._objectfold(
                'var o = { m: function (a, b) { return a + b; } }; console.log(o.m(p(), q()));'
            ),
        )

    def test_a_duplicate_parameter_keeps_the_dropped_argument(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                console.log(function(a, a) {
                  return a;
                }(g(), 1));
                """
            ),
            self._objectfold(
                'var o = { m: function (a, a) { return a; } }; console.log(o.m(g(), 1));'
            ),
        )

    def test_a_read_is_not_moved_across_the_write_beside_it(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x = 1;
                console.log(function(a, b) {
                  return b + a;
                }(x, x = 5));
                """
            ),
            self._objectfold(
                'var x = 1; var o = { m: function (a, b) { return b + a; } };'
                ' console.log(o.m(x, x = 5));'
            ),
        )

    def test_a_read_is_not_duplicated_around_the_write_beside_it(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x = 1;
                console.log(function(a, b) {
                  return a + b + a;
                }(x, x = 5));
                """
            ),
            self._objectfold(
                'var x = 1; var o = { m: function (a, b) { return a + b + a; } };'
                ' console.log(o.m(x, x = 5));'
            ),
        )

    def test_an_argument_behind_an_optional_chain_still_runs(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                console.log(function(a, b) {
                  return a?.[b];
                }(null, e()));
                """
            ),
            self._objectfold(
                'var o = { m: function (a, b) { return a?.[b]; } }; console.log(o.m(null, e()));'
            ),
        )

    def test_an_argument_is_not_moved_after_a_call_the_body_makes(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                console.log(function(a, b) {
                  return a() + b;
                }(f, g()));
                """
            ),
            self._objectfold(
                'var o = { m: function (a, b) { return a() + b; } }; console.log(o.m(f, g()));'
            ),
        )

    def test_a_pair_read_in_order_by_a_computed_member_is_substituted(self):
        self.assertEqual(
            'console.log(x()[y()]);',
            self._objectfold(
                'var o = { m: function (a, b) { return a[b]; } }; console.log(o.m(x(), y()));'
            ),
        )

    def test_an_effectful_argument_behind_a_logical_assignment_still_runs(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                console.log(function(a, k, b) {
                  return a[k] ||= b;
                }(obj, 'key', eff()));
                """
            ),
            self._objectfold(
                "var o = { m: function (a, k, b) { return a[k] ||= b; } };"
                " console.log(o.m(obj, 'key', eff()));"
            ),
        )

    def test_two_pure_calls_are_reordered_into_the_body(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function p() {
                  return 1;
                }
                function q() {
                  return 2;
                }
                console.log(q() + p());
                """
            ),
            self._objectfold(
                'function p() { return 1; } function q() { return 2; }'
                ' var o = { m: function (a, b) { return b + a; } }; console.log(o.m(p(), q()));'
            ),
        )


class TestAnArgumentReadUnderANestedScopeIsNotSubstituted(TestJsDeobfuscator):

    def test_an_identifier_read_inside_a_returned_arrow_is_not_substituted(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var f = function(a) {
                  return () => a;
                }(x);
                """
            ),
            self._objectfold(
                'var o = { m: function (a) { return () => a; } }; var f = o.m(x);'
            ),
        )

    def test_a_fresh_literal_read_inside_a_returned_arrow_is_not_substituted(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var f = function(a) {
                  return () => a;
                }([1, 2]);
                """
            ),
            self._objectfold(
                'var o = { m: function (a) { return () => a; } }; var f = o.m([1, 2]);'
            ),
        )

    def test_a_constant_literal_read_inside_a_returned_arrow_is_substituted(self):
        self.assertEqual(
            'var f = () => 5;',
            self._objectfold(
                'var o = { m: function (a) { return () => a; } }; var f = o.m(5);'
            ),
        )


class TestAFoldedFunctionKeepsItsIdentity(TestJsDeobfuscator):

    def test_a_function_naming_itself_is_not_cloned_per_site(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var o = { m: function f() {
                  return f;
                } };
                console.log(o.m() === o.m());
                """
            ),
            self._objectfold(
                'var o = { m: function f() { return f; } }; console.log(o.m() === o.m());'
            ),
        )

    def test_a_function_reading_its_callee_is_not_cloned_per_site(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var o = { m: function() {
                  return arguments.callee;
                } };
                console.log(o.m() === o.m());
                """
            ),
            self._objectfold(
                'var o = { m: function () { return arguments.callee; } };'
                ' console.log(o.m() === o.m());'
            ),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameAboutArgumentsTheFoldOwes(TestJsDeobfuscator):

    def test_each_argument_runs_once_and_in_the_order_it_is_written(self):
        rows = AN_ARGUMENT_WHOSE_EFFECT_THE_FOLD_OWES
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )
