"""
SECURITY: every program in this module is written by hand and benign; never add one taken from a
sample.
"""
from __future__ import annotations

import unittest

from inspect import cleandoc

from test import TestBase, opportunity
from test.lib.scripts.js.analysis.differential import behavior, host_behavior, node_executable
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator
from test.lib.scripts.js.ledger import STRING_TIMERS, on_separate_lines

from refinery.lib.scripts.js.deobfuscation import deobfuscate
from refinery.lib.scripts.js.deobfuscation.simplify import JsSimplifications
from refinery.lib.scripts.js.options import DeobfuscationOptions
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer
from refinery.units.scripting.djs import djs


#: Code run from a string above this read could replace `String.prototype.charAt`, so only the
#: trusting model folds it.
_JUNK = "console.log('abc'.charAt(1));"

_JUNK_FOLDED = "console.log('b');"


def _printed(source: str) -> str:
    return JsSynthesizer().convert(JsParser(source).parse())


def _deobfuscated(source: str, *, trust_eval: bool = False) -> str:
    ast = JsParser(source).parse()
    deobfuscate(ast, trust_eval=trust_eval)
    return JsSynthesizer().convert(ast)


class TestJsTrustedEvalExcusesTheSurfacesThatRunUnreadableCode(TestJsDeobfuscator):

    _RUNS_UNREADABLE_CODE = (
        'eval(input);',
        'var g = Function(payload);\nSINK(g);',
        'setTimeout(code, 10);',
    )

    def test_the_read_below_one_is_left_standing_by_default(self):
        for opener in self._RUNS_UNREADABLE_CODE:
            with self.subTest(opener):
                self.assertEqual(
                    _deobfuscated(on_separate_lines(opener, _JUNK)),
                    on_separate_lines(_printed(opener), _JUNK),
                )

    def test_the_read_below_one_is_folded_under_the_option(self):
        for opener in self._RUNS_UNREADABLE_CODE:
            with self.subTest(opener):
                self.assertEqual(
                    _deobfuscated(on_separate_lines(opener, _JUNK), trust_eval=True),
                    on_separate_lines(_printed(opener), _JUNK_FOLDED),
                )


class TestJsTrustedEvalDoesNotExcuseAMutationTheScriptWritesDown(TestJsDeobfuscator):

    _MUTATES_IN_PLAIN_SIGHT = (
        'String.prototype.charAt = q;',
        cleandoc("""
            with (String.prototype) {
              charAt = q;
            }
        """),
        cleandoc("""
            function f(a b) {
              return 1;
            }
        """),
    )

    def test_the_read_below_one_is_left_standing_by_default(self):
        for mutation in self._MUTATES_IN_PLAIN_SIGHT:
            with self.subTest(mutation):
                self.assertEqual(
                    _deobfuscated(on_separate_lines(mutation, _JUNK)),
                    on_separate_lines(_printed(mutation), _JUNK),
                )

    def test_the_read_below_one_is_left_standing_under_the_option_too(self):
        for mutation in self._MUTATES_IN_PLAIN_SIGHT:
            with self.subTest(mutation):
                self.assertEqual(
                    _deobfuscated(on_separate_lines(mutation, _JUNK), trust_eval=True),
                    on_separate_lines(_printed(mutation), _JUNK),
                )

    @opportunity
    def test_the_read_below_a_with_body_writing_another_name_is_folded_under_either_model(self):
        writes_another_name = cleandoc("""
            with (o) {
              x = 2;
            }
        """)
        for trust_eval in (False, True):
            with self.subTest(trust_eval=trust_eval):
                self.assertEqual(
                    _deobfuscated(on_separate_lines(writes_another_name, _JUNK), trust_eval=trust_eval),
                    on_separate_lines(_printed(writes_another_name), _JUNK_FOLDED),
                )

    def test_a_read_a_runtime_key_store_may_replace_is_left_standing_under_the_option(self):
        script = cleandoc("""
            var s = 'ab';
            globalThis[k] = 0;
            console.log(s.length);
        """)
        self.assertEqual(_deobfuscated(script, trust_eval=True), script)


class TestJsTrustedEvalDoesNotExcuseAnIndirectEval(TestJsDeobfuscator):

    _INDIRECT_EVAL = (
        'var e = eval;\ne(input);',
        'window.eval(input);',
    )

    def test_the_read_below_one_is_left_standing_under_the_option(self):
        for opener in self._INDIRECT_EVAL:
            with self.subTest(opener):
                self.assertEqual(
                    _deobfuscated(on_separate_lines(opener, _JUNK), trust_eval=True),
                    on_separate_lines(_printed(opener), _JUNK),
                )

    def test_a_computed_eval_destructuring_key_is_not_trusted(self):
        script = F"const {{Function, ['eval']: e}} = globalThis;\ne(input);\n{_JUNK}"
        self.assertEqual(
            _deobfuscated(script, trust_eval=True),
            F'const {{ Function, eval: e }} = globalThis;\ne(input);\n{_JUNK}',
        )

    def test_a_computed_variable_destructuring_key_is_not_trusted(self):
        script = F'const {{Function, [k]: e}} = globalThis;\ne(input);\n{_JUNK}'
        self.assertEqual(
            _deobfuscated(script, trust_eval=True),
            F'const {{ Function, [k]: e }} = globalThis;\ne(input);\n{_JUNK}',
        )


class TestJsTrustedEvalChangesNothingAboutAScriptThatRunsNoUnreadableCode(TestJsDeobfuscator):

    _CLOSED_WORLD_SCRIPTS = (
        "var a = 1 + 1;\nconsole.log(a);",
        "function f() {\n  return 'x';\n}\nconsole.log(f());",
        "console.log('abc'.charAt(1));",
    )

    def test_both_models_produce_the_same_output(self):
        for script in self._CLOSED_WORLD_SCRIPTS:
            with self.subTest(script):
                self.assertEqual(
                    _deobfuscated(script),
                    _deobfuscated(script, trust_eval=True),
                )


class TestJsTrustedEvalReachesATransformThatBuildsItsOwnCache(TestBase):

    _SCRIPT = F'eval(input);\n{_JUNK}'

    def _run_alone(self, trust_eval: bool) -> str:
        ast = JsParser(self._SCRIPT).parse()
        for _ in range(10):
            transform = JsSimplifications()
            transform.options = DeobfuscationOptions(trust_eval=trust_eval)
            transform.visit(ast)
            if not transform.changed:
                break
        return JsSynthesizer().convert(ast)

    def test_the_pass_leaves_the_read_standing_without_the_option(self):
        self.assertEqual(self._run_alone(False), self._SCRIPT)

    def test_the_pass_folds_the_read_under_the_option(self):
        self.assertEqual(self._run_alone(True), F'eval(input);\n{_JUNK_FOLDED}')


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestJsTrustedEvalReadsTheCodeAStringSpells(TestBase):

    def assertDeobfuscationBehavesAsTheProgramDoes(self, rows: dict[str, str]):
        self.assertEqual(
            {
                label: host_behavior(source.encode('utf8') | djs() | str, prelude=STRING_TIMERS)
                for label, source in rows.items()
            },
            {label: host_behavior(source, prelude=STRING_TIMERS) for label, source in rows.items()},
        )

    def test_a_top_level_name_the_code_reads_is_kept(self):
        self.assertDeobfuscationBehavesAsTheProgramDoes({
            'a function constructed with a parameter, reading a let': (
                "let k = 5; var add = new Function('a', 'return a + k'); console.log(add(1));"
            ),
            'a function constructed with a parameter, reading a var': (
                "var k = 5; var add = new Function('a', 'return a + k'); console.log(add(1));"
            ),
            'a body reading its arguments': (
                "let k = 5; console.log(Function('return k + arguments.length')());"
            ),
            'a body called under a local of the same name': (
                "var k = 5; function g() { var k = 1; return Function('return k')(); } console.log(g());"
            ),
            'a string timer declaring a let the file declares': (
                "let k = 1; setTimeout('let k = 2; console.log(k)', 0);"
            ),
            'a string timer reading a const': (
                "const k = 7; setTimeout('console.log(k)', 0);"
            ),
            'a body reading a name as a shorthand property': (
                "var k = 5; var g = new Function('a', 'return {k}'); console.log(g(1).k);"
            ),
            'a body calling a function declared in a block': (
                "{ function f() { return 'x'; } } var g = new Function('a', 'return a + f()'); console.log(g(1));"
            ),
        })

    def test_text_a_fold_spells_is_read(self):
        self.assertDeobfuscationBehavesAsTheProgramDoes({
            'a concatenated body': (
                "var k = 5; var add = new Function('a', 'return a + ' + 'k'); console.log(add(1));"
            ),
            'a body decoded from base64': (
                "var k = 5; var add = new Function('a', atob('cmV0dXJuIGEgKyBr')); console.log(add(1));"
            ),
            'a body held by a constant': (
                "var k = 5; var s = 'return a + k'; var add = new Function('a', s); console.log(add(1));"
            ),
            'a template body': (
                "var k = 5; var add = new Function('a', `return a + k`); console.log(add(1));"
            ),
        })

    def test_each_spelling_of_the_function_constructor_is_read(self):
        self.assertDeobfuscationBehavesAsTheProgramDoes({
            'an alias': (
                "var k = 5; var F = Function; var add = F('a', 'return a + k'); console.log(add(1));"
            ),
            'an alias used twice': (
                "var F = Function; var k = 5; var add = F('a', 'return a + k'); var sub = F('a', 'return a - k');"
                " console.log(add(1), sub(1));"
            ),
            'a member of the global object': (
                "var k = 5; var add = globalThis.Function('a', 'return a + k'); console.log(add(1));"
            ),
            'the constructor of a function': (
                "var k = 5; var add = (function () {}).constructor('a', 'return a + k'); console.log(add(1));"
            ),
            'the constructor of a constructor': (
                "var k = 5; var add = [].constructor.constructor('a', 'return a + k'); console.log(add(1));"
            ),
        })

    def test_a_write_the_code_makes_takes_effect_when_the_code_runs(self):
        self.assertDeobfuscationBehavesAsTheProgramDoes({
            'a body writing a var': (
                "var k = 5; var set = new Function('v', 'k = v'); set(7); console.log(k);"
            ),
            'a body writing a let': (
                "let k = 5; var set = new Function('v', 'k = v'); set(7); console.log(k);"
            ),
            'a body destructuring into a var': (
                "var k = 5; var g = new Function('v', '[k] = v'); g([7]); console.log(k);"
            ),
            'a body built before the var it writes': (
                "var set = new Function('v', 'k = v'); var k = 5; set(7); console.log(k);"
            ),
            'a body built before the let it writes': (
                "var set = new Function('v', 'k = v'); let k = 5; set(7); console.log(k);"
            ),
            'a body writing a name read before and after the call': (
                "var set = new Function('v', 'k = v; return arguments.length'); var k = 5; console.log(k); set(7);"
                " console.log(k);"
            ),
            'a string timer writing a var a callback reads': (
                "var k = 5; setTimeout('k = 6', 0); setTimeout(function () { console.log(k); }, 10);"
            ),
            'a string timer declaring a var the file declares': (
                "var k = 1; setTimeout('var k = 2; console.log(k)', 0); setTimeout(function () { console.log(k); }, 10);"
            ),
        })

    def test_code_spelled_inside_the_code_keeps_its_role(self):
        self.assertDeobfuscationBehavesAsTheProgramDoes({
            'an eval in a body, reading': (
                "var k = 5; var g = new Function('a', 'return eval(\"a + k\")'); console.log(g(1));"
            ),
            'an eval in a body, writing a var': (
                "var k = 5; var g = new Function('v', 'eval(\"k = v\"); return arguments.length'); g(7); console.log(k);"
            ),
            'an eval in a body, writing a let': (
                "let k = 5; var g = new Function('v', 'eval(\"k = v\"); return arguments.length'); g(7); console.log(k);"
            ),
            'a string timer in a body, writing': (
                "var k = 5; var set = new Function('v', 'setTimeout(\"k = 7\", 0)'); set(7);"
                " setTimeout(function () { console.log(k); }, 10);"
            ),
            'a body in a strict eval, writing': (
                "var k = 1; function f() { eval('\"use strict\"; Function(\"k = 2\")()'); return k; } console.log(f());"
            ),
        })

    def test_a_spelled_direct_eval_runs_in_its_function(self):
        self.assertDeobfuscationBehavesAsTheProgramDoes({
            'a strict eval reading a local': (
                "function f() { var k = 1; return eval('\"use strict\"; k + 1'); } console.log(f());"
            ),
            'a strict eval writing a local': (
                "function f() { var k = 1; eval('\"use strict\"; k = 2'); return k; } console.log(f());"
            ),
            'a strict eval writing arguments': (
                "function f(a) { eval('\"use strict\"; arguments[0] = 2'); return a; } console.log(f(1));"
            ),
            'a strict eval reading a copy of a parameter': (
                "function f(a) { var b = a; return eval('\"use strict\"; b'); } console.log(f(3));"
            ),
            'a strict eval reading its receiver': (
                "var o = { v: 3, f: function () { return eval('\"use strict\"; this.v'); } }; console.log(o.f());"
            ),
            'an eval declaring parseInt on one path': (
                "function f(c) { if (c) eval('var parseInt = function () { return 9; }'); return parseInt('5'); }"
                " console.log(f(1), f(0));"
            ),
            'an eval declaring String on one path': (
                "function f(c) { if (c) eval('var String = function () { return \"x\"; }'); return String(5); }"
                " console.log(f(1), f(0));"
            ),
            'an eval declaring undefined on one path': (
                "function f(c) { if (c) eval('var undefined = 4'); return undefined; } console.log(f(1), f(0));"
            ),
            'an eval declaring a global name on one path': (
                "var x = 1; function f(c) { if (c) eval('var x = 4'); return x; } console.log(f(1), f(0));"
            ),
            'an eval answering a closure that writes a later local': (
                "function f() { var set = eval('\"use strict\"; (function (v) { k = v; })'); var k = 1; set(2);"
                " return k; } console.log(f());"
            ),
            'a copied method running an eval': (
                "var o = { f: function () { return eval('\"use strict\"; typeof k'); } };"
                " function g(k) { console.log(k); return o.f(); } console.log(g(1));"
            ),
        })

    def test_a_name_the_code_reaches_through_the_global_object_is_kept(self):
        self.assertDeobfuscationBehavesAsTheProgramDoes({
            'a body reading globalThis.k': (
                "var k = 5; var g = new Function('a', 'return a + globalThis.k'); console.log(g(1));"
            ),
            'a body reading this.k': (
                "var k = 5; var g = new Function('a', 'return a + this.k'); console.log(g(1));"
            ),
            'a body writing globalThis.k': (
                "var k = 5; var g = new Function('v', 'globalThis.k = v; return arguments.length'); g(7); console.log(k);"
            ),
            'a body writing this.k': (
                "var k = 5; var g = new Function('v', 'this.k = v; return arguments.length'); g(7); console.log(k);"
            ),
        })

    def test_code_this_analysis_cannot_read_or_that_opens_the_world_keeps_every_name(self):
        self.assertDeobfuscationBehavesAsTheProgramDoes({
            'a body nested too deep for the parser': (
                "var k = 5; var g = new Function('a', 'return ' + '('.repeat(250) + 'a + k' + ')'.repeat(250));"
                " console.log(g(1));"
            ),
            'a parameter ending in a line comment': (
                "var k = 5; var g = new Function('a //', 'return a + k'); console.log(g(1));"
            ),
            'a body ending in a line comment': (
                "var k = 5; var g = new Function('a', 'return a + k // tail'); console.log(g(1));"
            ),
            'a body that does not parse': (
                "var k = 5; try { var g = new Function('a', 'return a +* k'); } catch (e) { console.log(e.name); }"
            ),
            'a body reading a global under a computed key': (
                "var k = 5; var g = new Function('a, n', 'return a + globalThis[n]'); console.log(g(1, 'k'));"
            ),
            'a body reading a name in a with': (
                "var k = 5; var g = new Function('o', 'with (o) { return k; }'); console.log(g({}));"
            ),
        })

    def test_a_built_in_the_code_replaces_is_not_folded(self):
        self.assertDeobfuscationBehavesAsTheProgramDoes({
            'a body replacing a method of String.prototype': (
                "var p = new Function('v', 'String.prototype.charAt = function () { return v; }'); p('x');"
                " console.log('abc'.charAt(1));"
            ),
            'a body replacing atob': (
                "new Function('atob = function (s) { return s; }; return arguments.length')(); console.log(atob('aGk='));"
            ),
        })

    def test_a_pass_asking_about_one_name_sees_the_code_that_names_it(self):
        self.assertDeobfuscationBehavesAsTheProgramDoes({
            'a global a function writes and a body reads': (
                "var k; function f() { k = 5; var g = new Function('a', 'return a + k'); return g(1); } console.log(f());"
            ),
            'an undeclared global a function writes and a body reads': (
                "function f() { k = 5; return new Function('a', 'return a + k')(1); } console.log(f());"
            ),
            'a body using the value a function returns': (
                "function f() { return 5; } f(); var g = new Function('return f() + 1'); console.log(g());"
            ),
            'a body writing a property of an object': (
                "var o = { x: 1 }; var g = new Function('o.x = 2'); g(); console.log(o.x);"
            ),
            'a body reading a property written after it is built': (
                "var o = { x: 1 }; var g = new Function('return o.x'); o.x = 2; console.log(g());"
            ),
        })

    def test_the_code_reads_what_runs_before_it(self):
        self.assertDeobfuscationBehavesAsTheProgramDoes({
            'a body called after a write': (
                "var k = 1; var g = new Function('a', 'return a + k'); k = 2; console.log(g(0));"
            ),
            'a string timer running after a write': (
                "let k = 1; setTimeout('console.log(k)', 0); k = 2;"
            ),
            'a body called after a write in a function': (
                "function f() { var g = new Function('a', 'return a + k'); k = 2; return g(0); } var k = 1;"
                " console.log(f());"
            ),
            'a body called after a store that a second store replaces': (
                "var k = 1; var g = new Function('a', 'return a + k'); k = 3; k = 2; console.log(g(0));"
            ),
        })

    def test_code_that_names_nothing_outside_itself_keeps_nothing(self):
        self.assertDeobfuscationBehavesAsTheProgramDoes({
            'a body answering the global object': (
                "var junk = 1; var g = Function('return this'); console.log(typeof g());"
            ),
            'a body beside a call of a built-in': (
                "var g = new Function('a', 'return a'); console.log('abc'.charAt(1), g(2));"
            ),
            'a body whose parameter has the name of a global': (
                "var k = 5; var id = new Function('k', 'return k'); console.log(id(1));"
            ),
        })

    def test_a_commonjs_var_is_not_a_name_the_code_finds(self):
        source = "var k = 5; var add = new Function('a', 'return a + k'); console.log(add(1));"
        self.assertEqual(behavior(source.encode('utf8') | djs(commonjs=True) | str), behavior(source))
