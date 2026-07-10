from __future__ import annotations

import inspect

from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator

from refinery.lib.scripts.js.deobfuscation.antidbg import JsRemoveReDoS


class TestAntiDebug(TestJsDeobfuscator):

    _DEFENSE_CODE = (
        "var a = (function() {"
        "  var b = true;"
        "  return function(c, d) {"
        "    var e = b ? function() {"
        "      if (d) { var f = d.apply(c, arguments); return d = null, f; }"
        "    } : function() {};"
        "    return b = false, e;"
        "  };"
        "}()), g = a(this, function() {"
        "  return g.toString().search('(((.+)+)+)+$')"
        "    .toString().constructor(g).search('(((.+)+)+)+$');"
        "});"
    )

    def test_remove_self_defending_redos(self):
        source = self._DEFENSE_CODE + (
            "g();"
            "console.log('hello');"
        )
        self.assertEqual(self._deobfuscate(source), "console.log('hello');")

    def test_preserves_code_without_redos(self):
        source = inspect.cleandoc(
            """
            var x = 1;
            console.log(x);
            """
        )
        self.assertEqual(source, self._run_transformer(source, JsRemoveReDoS))

    def test_redos_factory_preserved_when_referenced(self):
        source = self._DEFENSE_CODE + (
            "g();"
            "var other = a(this, function() { return 42; });"
            "console.log(other);"
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                var a = function() {
                  var b = true;
                  return function(c, d) {
                    var e = b ? function() {
                      if (d) {
                        var f = d.apply(c, arguments);
                        return d = null, f;
                      }
                    } : function() {};
                    return b = false, e;
                  };
                }();
                var other = a(this, function() {
                  return 42;
                });
                console.log(other);
                """
            ),
            self._deobfuscate(source),
        )

    def test_factory_removed_despite_same_name_in_other_scope(self):
        source = (
            'var fac = function() { return 1; };'
            " var g = fac('(((.+)+)+)+$');"
            ' g();'
            ' function other() { var fac = 7; return fac; }'
            ' console.log(other());'
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function other() {
                  var fac = 7;
                  return fac;
                }
                console.log(other());
                """
            ),
            self._run_transformer(source, JsRemoveReDoS),
        )
