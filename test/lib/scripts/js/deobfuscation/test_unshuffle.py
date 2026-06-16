from __future__ import annotations

import inspect

from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator

from refinery.lib.scripts.js.deobfuscation.namespaces import JsNamespaceFlattening
from refinery.lib.scripts.js.deobfuscation.unshuffle import JsArrayUnshuffle
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer


class TestArrayUnshuffle(TestJsDeobfuscator):

    def _unshuffle(self, source: str) -> str:
        return self._run_transformer(source, JsArrayUnshuffle)

    def test_direct_callee_in_rotation_names(self):
        source = inspect.cleandoc(
            """
            function rot(arr, n) {
              for (var i = 0; i < n; i++) arr.push(arr.shift());
              return arr;
            }
            var x = rot(["b", "c", "d", "e", "f", "g", "h", "i", "j", "a"], 9);
            """
        )
        result = self._unshuffle(source)
        self.assertEqual(
            inspect.cleandoc(
                """
                function rot(arr, n) {
                  for (var i = 0; i < n; i++) {
                    arr.push(arr.shift());
                  }
                  return arr;
                }
                var x = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"];
                """
            ),
            result,
        )

    def test_namespace_qualified_callee_with_empty_object(self):
        source = inspect.cleandoc(
            """
            var NS = {};
            NS.rot = function(arr, n) {
              for (var i = 0; i < n; i++) arr.push(arr.shift());
              return arr;
            };
            var x = NS.rot(["b", "c", "d", "e", "f", "g", "h", "i", "j", "a"], 9);
            """
        )
        ast = JsParser(source).parse()
        JsNamespaceFlattening().visit(ast)
        JsArrayUnshuffle().visit(ast)
        result = JsSynthesizer().convert(ast)
        self.assertEqual(
            inspect.cleandoc(
                """
                function rot(arr, n) {
                  for (var i = 0; i < n; i++) {
                    arr.push(arr.shift());
                  }
                  return arr;
                }
                var x = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"];
                """
            ),
            result,
        )

    def test_namespace_qualified_callee_without_empty_object_rejected(self):
        source = inspect.cleandoc(
            """
            var utils = require("utils");
            var x = utils.process(["b", "c", "d", "e", "f", "g", "h", "i", "j", "a"], 9);
            """
        )
        self.assertEqual(source, self._unshuffle(source))
