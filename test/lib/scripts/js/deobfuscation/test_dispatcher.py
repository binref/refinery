from __future__ import annotations

from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator

from refinery.lib.scripts.js.analysis.cache import ModelCache
from refinery.lib.scripts.js.deobfuscation.dispatcher import JsDispatcherUnwrapper
from refinery.lib.scripts.js.model import JsFunctionDeclaration
from refinery.lib.scripts.js.parser import JsParser


class TestDispatcherUnwrapping(TestJsDeobfuscator):

    def _make_dispatcher(self, dict_lines: list, tail_lines: list):
        return '\n'.join((
            'var c = Object["create"](null);',
            'var p;',
            'function d(name, flag, rtype, lengths) {',
            '  var output;',
            '  var fns = {',
            *dict_lines,
            '  };',
            '  if (flag === "initF") { p = []; }',
            '  if (flag === "createF") {',
            '    output = c[name] || (c[name] = fns[name]);',
            '  } else {',
            '    output = fns[name]();',
            '  }',
            '  if (rtype === "wrapF") { return { "wk": output }; }',
            '  else { return output; }',
            '}',
            'function stub() {}',
            *tail_lines,
        ))

    def test_single_function_direct_call(self):
        source = self._make_dispatcher(
            dict_lines=[
                '"abc": function() { var [x] = p; return x + 1; }'
            ],
            tail_lines=[
                'console.log((p = [5], d("abc")));'
            ]
        )
        self.assertEqual('console.log(6);', self._deobfuscate(source))

    def test_multi_function_dispatcher(self):
        source = self._make_dispatcher(
            dict_lines=[
                '"f1": function() { var [a, b] = p; return a + b; },',
                '"f2": function() { var [a, b] = p; return a * b; }',
            ],
            tail_lines=[
                'var x = (p = [2, 3], d("f1"));',
                'var y = (p = [x, 4], d("f2"));',
                'console.log(y);',
            ]
        )
        self.assertEqual('console.log(20);', self._deobfuscate(source))

    def test_wrapped_reference(self):
        source = self._make_dispatcher(
            dict_lines=[
                '"id": function() { var [x] = p; return x; }',
            ],
            tail_lines=[
                'var fn = new d("id", "createF", "wrapF")["wk"];',
                'console.log(fn(42));',
            ]
        )
        self.assertEqual('console.log(42);', self._deobfuscate(source))

    def test_boilerplate_removal(self):
        source = self._make_dispatcher(
            dict_lines=[
                '"k": function() { return 42; }',
            ],
            tail_lines=[
                'console.log(d("k"));'
            ]
        )
        result = self._deobfuscate(source)
        self.assertEqual('console.log(42);', result)

    def test_unwrapping_invalidates_shared_model_cache(self):
        """
        Unwrapping removes the dispatcher's empty stub function through the shared analysis cache.
        When neither the payload nor the cache declarator is in removable form, that stub deletion
        is the unwrapper's only boilerplate removal, so the removal itself must invalidate the shared
        cache: a later transform sharing the cache must not observe a model that still declares the
        already-deleted stub.
        """
        source = '\n'.join((
            'var c = {};',
            'var p = 0;',
            'function d(name, flag, rtype, lengths) {',
            '  var output;',
            '  var fns = {',
            '    "k": function() { return 42; }',
            '  };',
            '  if (flag === "initF") { p = []; }',
            '  if (flag === "createF") {',
            '    output = c[name] || (c[name] = fns[name]);',
            '  } else {',
            '    output = fns[name]();',
            '  }',
            '  if (rtype === "wrapF") { return { "wk": output }; }',
            '  else { return output; }',
            '}',
            'function stub() {}',
            'console.log(d("k"));',
        ))
        ast = JsParser(source).parse()
        cache = ModelCache(ast)
        transformer = JsDispatcherUnwrapper()
        transformer.models = cache
        transformer.visit(ast)
        remaining = sorted(
            node.id.name
            for node in ast.walk()
            if isinstance(node, JsFunctionDeclaration) and node.id is not None
        )
        self.assertEqual(['k'], remaining)
        self.assertIsNone(cache.model.lookup('stub', cache.model.root_scope))
