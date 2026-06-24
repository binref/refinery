from __future__ import annotations

import inspect

from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator


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
                y(undefined);
                """
            ),
            self._objectfold(source),
        )

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
