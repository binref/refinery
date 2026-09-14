"""
The anchored tampering oracle: whether the built-ins a fold or an interpreted execution is about to
trust still mean what the language says at one point in the program — the anchor. Every refuse row
here is a program one textual spelling away from its clear twin: the tampering site removed, or
moved after the anchor, must fold. The interpreter rows hold the anchor the evaluation route passes
— the call node being executed — and show the trust that clearance buys where the program-wide
questions refuse on the surface alone.

SECURITY: every program here is hand-authored in this file and benign. No sample and no stored
obfuscator fixture may be fed to this.
"""
from __future__ import annotations

import time

from test import TestBase

from refinery.lib.scripts import Node, _remove_from_parent
from refinery.lib.scripts.js.analysis.cache import ModelCache
from refinery.lib.scripts.js.deobfuscation.interpreter import InterpreterError, JsInterpreter
from refinery.lib.scripts.js.model import (
    JsCallExpression,
    JsIdentifier,
    JsMemberExpression,
    JsNumericLiteral,
)
from refinery.lib.scripts.js.options import DeobfuscationOptions
from refinery.lib.scripts.js.parser import JsParser

#: Every refuse row's anchor: the first `String.fromCharCode` call, the builtin the tampering
#: sites in these programs are all spelled against.
_FROM_CHAR_CODE = 'fromCharCode'


def _call_with_property(ast: Node, property_name: str) -> JsCallExpression:
    for node in ast.walk():
        if (
            isinstance(node, JsCallExpression)
            and isinstance(node.callee, JsMemberExpression)
            and isinstance(node.callee.property, JsIdentifier)
            and node.callee.property.name == property_name
        ):
            return node
    raise AssertionError(F'no call to a .{property_name} method')


def _call_of_name(ast: Node, callee_name: str) -> JsCallExpression:
    for node in ast.walk():
        if (
            isinstance(node, JsCallExpression)
            and isinstance(node.callee, JsIdentifier)
            and node.callee.name == callee_name
        ):
            return node
    raise AssertionError(F'no call to {callee_name}')


_A_SITE_BEFORE_THE_ANCHOR = {
    'an opaque write through a spelled global base': (
        'var k, v;\nglobalThis[k] = v;\nString.fromCharCode(65);'
    ),
    'an opaque compound write': (
        'var k, v;\nglobalThis[k] += 1;\nString.fromCharCode(65);'
    ),
    'an opaque update write': (
        'var k;\nglobalThis[k]++;\nString.fromCharCode(65);'
    ),
    'an opaque delete': (
        'var k;\ndelete globalThis[k];\nString.fromCharCode(65);'
    ),
    'a write in a function invoked both before and after': (
        'function g() { return String.fromCharCode(65); }\n'
        'g();\nvar k, v;\nglobalThis[k] = v;\ng();'
    ),
    'a construction-valued name passed as a callback': (
        'var t = Function("this.String = 9;");\n[0].forEach(t);\nString.fromCharCode(65);'
    ),
    'an eval-alias call before the anchor': (
        'var e = eval;\ne("String = 9");\nString.fromCharCode(65);'
    ),
    'a string timer before the anchor': (
        'setTimeout("String = 9", 0);\nString.fromCharCode(65);'
    ),
    'a static import anywhere': (
        'import x from "y";\nString.fromCharCode(65);'
    ),
    'a with statement anywhere': (
        'var o, x;\nwith (o) { x = 1; }\nString.fromCharCode(65);'
    ),
    'a span of source the model never read': (
        'var k = "abc\n;String.fromCharCode(65);'
    ),
    'a loop the anchor re-executes in': (
        'var c, k, v;\nwhile (c) { String.fromCharCode(65); globalThis[k] = v; }'
    ),
    'an alias invoked twice across the site': (
        'var k, v;\n'
        'function g() { String.fromCharCode(65); globalThis[k] = v; }\n'
        'var q = g;\nq();\nq();'
    ),
    'an unbound immediate construction': (
        'Function("this.String = 9")();\nString.fromCharCode(65);'
    ),
    'a construction held in a container': (
        'var fns = [Function("String = 9")];\nfns[0]();\nString.fromCharCode(65);'
    ),
    'a construction held as an object member': (
        'var o = { m: Function("String = 9") };\no.m();\nString.fromCharCode(65);'
    ),
    'a construction returned by a factory': (
        'function mk() { return { f: Function("String = 9") }; }\n'
        'mk().f();\nString.fromCharCode(65);'
    ),
    'a construction handed to sort': (
        'var g = Function;\n["String = 9", "p"].sort(g);\nString.fromCharCode(65);'
    ),
    'a construction handed to forEach': (
        '[0].forEach(Function("this.String = 9"));\nString.fromCharCode(65);'
    ),
    'a potential arguments.callee read': (
        'var k, v;\n'
        '(function () {\n'
        '  String.fromCharCode(65);\n'
        '  globalThis[k] = v;\n'
        '  arguments.callee();\n'
        '})();'
    ),
    'a computed arguments.callee read': (
        'var k, v;\n'
        '(function () {\n'
        '  String.fromCharCode(65);\n'
        '  globalThis[k] = v;\n'
        "  arguments['callee']();\n"
        '})();'
    ),
    'a runtime-keyed re-entry read off the arguments object': (
        'var k, v, i;\n'
        '(function () {\n'
        '  String.fromCharCode(65);\n'
        '  globalThis[k] = v;\n'
        "  i = 'callee';\n"
        '  arguments[i]();\n'
        '})();'
    ),
    'a potential .caller read': (
        'var k, v;\n'
        '(function () {\n'
        '  String.fromCharCode(65);\n'
        '  globalThis[k] = v;\n'
        '  arguments.callee.call(null);\n'
        '})();'
    ),
    'a parameter-base write through a handed-over global': (
        'var k, v;\nfunction t(x) { x[k] = v; }\nt(globalThis);\nString.fromCharCode(65);'
    ),
    'the global object handed to Reflect.set': (
        'Reflect.set(globalThis, "String", 9);\nString.fromCharCode(65);'
    ),
    'an eval re-invoking the enclosing activation': (
        'function g() { String.fromCharCode(65); globalThis.eval("String = 9; g()"); }\ng();'
    ),
    'a stored-code eval re-invoking the activation': (
        'var c = "String = 9; g()";\n'
        'function g() { String.fromCharCode(65); (0, eval)(c); }\ng();'
    ),
    'a timer re-invoking the enclosing activation': (
        'function g() { String.fromCharCode(65); setTimeout("String = 9; g()", 0); }\ng();'
    ),
    'a script-scope named activation under a surface': (
        'var k, v;\nvar e = eval;\n'
        'function g() { String.fromCharCode(65); globalThis[k] = v; }\ng();'
    ),
    'a constructed function invoked before the anchor': (
        'var f = new Function("this.String = 9");\nf();\nString.fromCharCode(65);'
    ),
    'a destructured eval invoked': (
        'const {eval} = globalThis;\neval("String = 9");\nString.fromCharCode(65);'
    ),
}
"""
The enumeration's every arm as a defeat: a computed-key store through a base that may be the
global object (each store form), a read of the object in an argument position (the hand-over and
`Reflect.set` spellings), a code-execution surface, a construction followed to every position
that obtains its value, and the multiplicity family — re-entry spellings, aliases, loops, and a
named activation reflective text could re-invoke.
"""

_A_SITE_THE_ANCHOR_ESCAPED = {
    'a write in a function invoked only later': (
        'var k, v;\nString.fromCharCode(65);\nfunction h() { globalThis[k] = v; }\nh();'
    ),
    'a computed-literal alias write': (
        'var g = globalThis;\ng["String"] = 9;\nString.fromCharCode(65);'
    ),
    'a construction invoked only after the anchor': (
        'String.fromCharCode(65);\nvar g = Function;\nvar s = g("return 1");\ns();'
    ),
    'a destructured intrinsic never invoked': (
        'String.fromCharCode(65);\nconst {eval} = globalThis;'
    ),
    'a fold inside a loop in a clean program': (
        'var s = 0;\nfor (var i = 0; i < 3; i++) { s = String.fromCharCode(65); }'
    ),
    'a twice-called function in a clean program': (
        'function g() { return String.fromCharCode(65); }\ng();\ng();'
    ),
    'a benign construction': (
        'var d = new Date();\nd.getTime();\nString.fromCharCode(65);'
    ),
    'a script-scope named activation with the surface removed': (
        'var k, v;\nfunction g() { String.fromCharCode(65); globalThis[k] = v; }\ng();'
    ),
    'a computed dispatch on a list base': (
        'var k, v, i;\n'
        'var names = ["callee", "caller"];\n'
        'function g(name) { globalThis[name] = v; }\n'
        'String.fromCharCode(65);\n'
        'i = 0;\n'
        'g(names[i]);'
    ),
    'a runtime-keyed read off a strict arguments object': (
        'var k, v, i, out;\n'
        '(function () {\n'
        "  'use strict';\n"
        '  String.fromCharCode(65);\n'
        '  globalThis[k] = v;\n'
        "  i = 'callee';\n"
        '  out = arguments[i];\n'
        '})();'
    ),
}
"""
Each refuse row's twin. The computed-literal alias write clears by design — a written *name* is
the per-name arm's question, not the oracle's — and the `new` predicate clears a construction
that is not `Function`, which is what keeps `new Date()` from refusing every anchor in a real
program.
"""


class TestBuiltinsIntactAt(TestBase):
    """
    The oracle's own verdicts, asked of the anchor every refuse program spells the same way.
    """

    def _verdict(self, source: str) -> bool:
        ast = JsParser(source).parse()
        return ModelCache(ast).builtins_intact_at(_call_with_property(ast, _FROM_CHAR_CODE))

    def test_every_site_before_the_anchor_refuses(self):
        for label, source in _A_SITE_BEFORE_THE_ANCHOR.items():
            with self.subTest(label):
                self.assertFalse(self._verdict(source))

    def test_every_site_the_anchor_escapes_clears(self):
        for label, source in _A_SITE_THE_ANCHOR_ESCAPED.items():
            with self.subTest(label):
                self.assertTrue(self._verdict(source))

    def test_an_entrypoint_matched_activation_refuses_under_the_option(self):
        """
        The host may invoke a named top-level function an unbounded number of times with no caller
        in the file, so its activation breaks multiplicity wherever a site exists — only under the
        option that names it.
        """
        source = (
            'var k, v;\n'
            'function g() {\n'
            '  var r = String.fromCharCode(65);\n'
            '  globalThis[k] = v;\n'
            '  return r;\n'
            '}\n'
            'g();'
        )
        ast = JsParser(source).parse()
        anchor = _call_with_property(ast, _FROM_CHAR_CODE)
        self.assertTrue(ModelCache(ast).builtins_intact_at(anchor))
        options = DeobfuscationOptions(entrypoints=('g',))
        self.assertFalse(ModelCache(ast, options).builtins_intact_at(anchor))


class TestSingularValueAt(TestBase):
    """
    The positioned value question: which single value a binding holds at the moment a given read
    evaluates it. Every program with an `eval` in it makes the binding volatile program-wide; the
    rows here draw where ordering repairs that — the hazard provably runs after the read, the
    value established before it, the read at most once — and where each leg refuses. The volatile
    locals all live inside an anonymous immediately-invoked function, the shape the sample's
    payload spells: a named script-scope activation is one the oracle's own multiplicity walk
    refuses under a reflection surface, which is its line and not this query's.
    """

    @staticmethod
    def _value_at(source: str):
        ast = JsParser(source).parse()
        cache = ModelCache(ast)
        read = next(
            n for n in ast.walk()
            if isinstance(n, JsIdentifier) and n.name == 'x' and cache.model.is_reference(n)
        )
        return cache.tampering.singular_value_at(cache.model.resolve(read), read)

    def test_an_eval_after_the_read_repairs_the_volatility(self):
        value = self._value_at(
            'var out;\n'
            'var q = (function () {\n'
            '  var x = 1;\n'
            '  out = x;\n'
            '  eval(payload);\n'
            '})();'
        )
        self.assertIsInstance(value, JsNumericLiteral)
        self.assertEqual(value.value, 1)

    def test_an_eval_before_the_read_refuses(self):
        self.assertIsNone(self._value_at(
            'var out;\n'
            'var q = (function () {\n'
            '  var x = 1;\n'
            '  eval(payload);\n'
            '  out = x;\n'
            '})();'
        ))

    def test_a_never_invoked_sibling_eval_is_no_hazard(self):
        value = self._value_at(
            'var out;\n'
            'var q = (function () {\n'
            '  var x = 1;\n'
            '  out = x;\n'
            '  var g = function () { eval(payload); };\n'
            '})();'
        )
        self.assertIsInstance(value, JsNumericLiteral)
        self.assertEqual(value.value, 1)

    def test_a_read_on_a_cycle_refuses_the_repair(self):
        self.assertIsNone(self._value_at(
            'var out = [];\n'
            'var q = (function () {\n'
            '  var x = 1;\n'
            '  for (var i = 0; i < 2; i++) {\n'
            '    out.push(x);\n'
            '    eval(payload);\n'
            '  }\n'
            '})();'
        ))

    def test_a_do_while_read_before_a_post_loop_eval_stays_refused(self):
        self.assertIsNone(self._value_at(
            'var out = [];\n'
            'var q = (function () {\n'
            '  var x = 1;\n'
            '  var i = 0;\n'
            '  do { out.push(x); i++; } while (i < 2);\n'
            '  eval(payload);\n'
            '})();'
        ))

    def test_a_two_channel_binding_gets_no_repair(self):
        self.assertIsNone(self._value_at(
            'var out;\n'
            'var q = (function () {\n'
            '  var x = 1;\n'
            '  x = 2;\n'
            '  out = x;\n'
            '  eval(payload);\n'
            '})();'
        ))

    def test_a_parameter_gets_no_repair(self):
        self.assertIsNone(self._value_at(
            'var out;\n'
            'var q = (function (x) {\n'
            '  out = x;\n'
            '  eval(payload);\n'
            '})(7);'
        ))

    def test_a_script_scope_binding_fails_closed(self):
        source = (
            'var out;\n'
            'var x = 1;\n'
            'out = x;\n'
            'eval(payload);'
        )
        ast = JsParser(source).parse()
        cache = ModelCache(ast)
        read = next(
            n for n in ast.walk()
            if isinstance(n, JsIdentifier) and n.name == 'x' and cache.model.is_reference(n)
        )
        binding = cache.model.resolve(read)
        self.assertEqual(cache.model.singular_value(binding).value, 1)
        self.assertIsNone(cache.tampering.singular_value_at(binding, read))

    def test_a_read_before_its_declarator_refuses(self):
        self.assertIsNone(self._value_at(
            'var out;\n'
            'var q = (function () {\n'
            '  out = x;\n'
            '  var x = 1;\n'
            '  eval(payload);\n'
            '})();'
        ))

    def test_a_splice_during_a_pinned_window_does_not_leak_past_the_pass(self):
        source = (
            'var out;\n'
            'var q = (function () {\n'
            '  var x = 1;\n'
            '  eval(payload);\n'
            '  out = x;\n'
            '})();'
        )
        ast = JsParser(source).parse()
        cache = ModelCache(ast)
        read = next(
            n for n in ast.walk()
            if isinstance(n, JsIdentifier) and n.name == 'x' and cache.model.is_reference(n)
        )
        binding = cache.model.resolve(read)
        self.assertIsNone(cache.tampering.singular_value_at(binding, read))
        with cache.pinned():
            _remove_from_parent(next(
                n for n in ast.walk()
                if isinstance(n, JsCallExpression)
                and isinstance(n.callee, JsIdentifier) and n.callee.name == 'eval'
            ).parent)
            self.assertIsNone(cache.tampering.singular_value_at(binding, read))
        self.assertEqual(cache.tampering.singular_value_at(binding, read).value, 1)


class TestAnAnchoredInterpreterTrustsWhatTheOracleCleared(TestBase):
    """
    The trust the interpreter's arms buy with an anchor: the program-wide questions refuse on the
    presence of a surface or a write alone, the oracle on whether it ran before the anchor, and
    each row shows both — the anchored execution answering what the program answers, the
    un-anchored one refusing.
    """

    def _execute(self, source: str, anchor_of, expression_of) -> object:
        """
        The anchored evaluation of *expression_of* over *source*, anchored at *anchor_of*.
        """
        ast = JsParser(source).parse()
        cache = ModelCache(ast)
        interpreter = JsInterpreter(
            effects=cache.effects,
            model=cache.model,
            anchor=anchor_of(ast),
            tampering=cache.tampering,
        )
        return interpreter.eval_expression(expression_of(ast))

    @staticmethod
    def _unanchored_refuses(source: str, expression_of) -> bool:
        """
        Whether the same expression, evaluated with no anchor, is refused — the program-wide
        refusal the oracle's clearance replaces.
        """
        ast = JsParser(source).parse()
        cache = ModelCache(ast)
        try:
            JsInterpreter(effects=cache.effects, model=cache.model).eval_expression(
                expression_of(ast))
        except InterpreterError:
            return True
        return False

    def test_a_method_call_folds_under_a_write_the_anchor_precedes(self):
        source = (
            'var k, v;\n'
            'function f() {\n'
            '  var r = String.fromCharCode(65);\n'
            '  globalThis[k] = v;\n'
            '  return r;\n'
            '}\n'
            'f();'
        )
        expression = lambda ast: _call_with_property(ast, _FROM_CHAR_CODE)
        self.assertTrue(self._unanchored_refuses(source, expression))
        self.assertEqual(self._execute(source, expression, expression), 'A')

    def test_a_method_call_still_refuses_under_a_write_that_precedes_the_anchor(self):
        source = (
            'var k, v;\n'
            'function f() {\n'
            '  globalThis[k] = v;\n'
            '  return String.fromCharCode(65);\n'
            '}\n'
            'f();'
        )
        expression = lambda ast: _call_with_property(ast, _FROM_CHAR_CODE)
        with self.assertRaises(InterpreterError):
            self._execute(source, expression, expression)

    def test_a_for_in_walk_reads_a_clean_chain_at_the_anchor(self):
        source = (
            'var e = eval;\n'
            'function f(o) {\n'
            '  var s = "";\n'
            '  for (var key in o) { s += key; }\n'
            '  return s;\n'
            '}\n'
            'f({a: 1, b: 2});'
        )
        self.assertTrue(self._unanchored_refuses(source, lambda ast: _call_of_name(ast, 'f')))
        self.assertEqual(
            self._execute(
                source,
                lambda ast: _call_of_name(ast, 'f'),
                lambda ast: _call_of_name(ast, 'f')),
            'ab',
        )

    def test_a_for_of_walk_reads_a_clean_chain_at_the_anchor(self):
        source = (
            'var e = eval;\n'
            'function f(a) {\n'
            '  var s = "";\n'
            '  for (var item of a) { s += item; }\n'
            '  return s;\n'
            '}\n'
            'f(["a", "b"]);'
        )
        self.assertTrue(self._unanchored_refuses(source, lambda ast: _call_of_name(ast, 'f')))
        self.assertEqual(
            self._execute(
                source,
                lambda ast: _call_of_name(ast, 'f'),
                lambda ast: _call_of_name(ast, 'f')),
            'ab',
        )

    def test_an_absent_property_read_answers_undefined_at_the_anchor(self):
        source = (
            'var e = eval;\n'
            'function f(o) {\n'
            '  return o.zz;\n'
            '}\n'
            'f({a: 1});'
        )
        self.assertTrue(self._unanchored_refuses(source, lambda ast: _call_of_name(ast, 'f')))
        self.assertIsNone(
            self._execute(
                source,
                lambda ast: _call_of_name(ast, 'f'),
                lambda ast: _call_of_name(ast, 'f')),
        )

    def test_an_attributed_prototype_write_still_refuses_at_the_anchor(self):
        """
        The per-name arm stays independent of the oracle: a written `Object` refuses the chain
        question through the anchored arm exactly as it does through the program-wide one.
        """
        source = (
            'Object.prototype.z = 9;\n'
            'function f(o) {\n'
            '  var s = "";\n'
            '  for (var key in o) { s += key; }\n'
            '  return s;\n'
            '}\n'
            'f({a: 1});'
        )
        with self.assertRaises(InterpreterError):
            self._execute(
                source,
                lambda ast: _call_of_name(ast, 'f'),
                lambda ast: _call_of_name(ast, 'f'))

    def test_the_child_interpreter_forwards_the_anchor(self):
        """
        A call the interpreted body makes runs in a child interpreter; the anchor it asks the
        oracle through is the one this execution started with, so a builtin the nested call reads
        folds under the same clearance the outer one did.
        """
        source = (
            'var k, v;\n'
            'function g() { return String.fromCharCode(65); }\n'
            'function f() { return g(); }\n'
            'var r = f();\n'
            'globalThis[k] = v;'
        )
        self.assertEqual(
            self._execute(
                source,
                lambda ast: _call_of_name(ast, 'f'),
                lambda ast: _call_of_name(ast, 'f')),
            'A',
        )


class TestManyAnchorsShareOneEnumeration(TestBase):
    """
    The site list is computed once per model lifetime, so a program with many anchors answers
    them all within a bound a per-anchor re-derivation would not meet — the model-thrash history
    made explicit.
    """

    def test_every_anchor_answers_within_the_bound(self):
        body = ['function f() {']
        for index in range(1000):
            body.append(F'  var r{index} = String.fromCharCode(65);')
        for index in range(8):
            body.append(F'  globalThis[k{index}] = v{index};')
        body.append('  return r0;')
        body.append('}')
        declarations = ', '.join(F'k{index}, v{index}' for index in range(8))
        source = F'var {declarations};\n' + '\n'.join(body) + '\nvar r = f();'
        ast = JsParser(source).parse()
        cache = ModelCache(ast)
        anchors = [
            node for node in ast.walk()
            if isinstance(node, JsCallExpression)
            and isinstance(node.callee, JsMemberExpression)
            and isinstance(node.callee.property, JsIdentifier)
            and node.callee.property.name == _FROM_CHAR_CODE
        ]
        self.assertEqual(len(anchors), 1000)
        started = time.perf_counter()
        verdicts = [cache.builtins_intact_at(anchor) for anchor in anchors]
        elapsed = time.perf_counter() - started
        self.assertTrue(all(verdicts))
        self.assertLess(elapsed, 30.0)
