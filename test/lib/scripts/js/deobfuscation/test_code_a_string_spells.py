"""
SECURITY: every program in this module is written by hand and benign; never add one taken from a
sample.
"""
from __future__ import annotations

import functools
import unittest

from test import (
    TestBase,
    a_property_of_the_pin_itself,
    backlog,
    fastest_processor_time,
    opportunity,
    processor_time_ratio,
    todo,
)
from test.lib.scripts.js.analysis.differential import behavior, host_behavior, node_executable
from test.lib.scripts.js.deobfuscation.test_dispatcher import a_dispatcher
from test.lib.scripts.js.ledger import STRING_TIMERS

from refinery.lib.scripts.js.deobfuscation import deobfuscate
from refinery.lib.scripts.js.parser import JsParser
from refinery.units.scripting.djs import djs

_EITHER_MODEL = (False, True)

_THE_SUSPECTING_MODEL = (True,)

#: A host function the program calls by name, which writes a global the program reads.
_A_HOST_FUNCTION_WRITING_RESULT = 'globalThis.hostRun = function () { globalThis.result = 42; };'

_A_FUNCTION_READING_ITS_CALLER = "function inner() { return inner.caller === null ? 'top' : 'fn'; }"

_A_FUNCTION_READING_ITS_CALLER_IN_A_BODY = (
    "function inner() { return Function('return inner.caller === null ? \"top\" : \"fn\"')(); }"
)


def _model(strict: bool) -> str:
    return 'the suspecting model' if strict else 'the default model'


def _deobfuscated(source: str, strict: bool, environment: str = 'universal') -> str:
    return source.encode('utf8') | djs(strict=strict, environment=environment) | str


class _NodeDecides(TestBase):

    def assertEachModelBehavesAsTheProgramDoes(
        self,
        rows: dict[str, str],
        *,
        models: tuple[bool, ...] = _EITHER_MODEL,
        host: str = '',
        environment: str = 'universal',
    ):
        prelude = STRING_TIMERS + host
        self.assertEqual(
            {
                (label, _model(strict)): host_behavior(_deobfuscated(source, strict, environment), prelude=prelude)
                for label, source in rows.items()
                for strict in models
            },
            {
                (label, _model(strict)): host_behavior(source, prelude=prelude)
                for label, source in rows.items()
                for strict in models
            },
        )

    def assertEachModelPrints(self, rows: dict[str, str], *, models: tuple[bool, ...] = _EITHER_MODEL):
        self.assertEqual(
            {(source, _model(strict)): _deobfuscated(source, strict) for source in rows for strict in models},
            {(source, _model(strict)): output for source, output in rows.items() for strict in models},
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestEitherModelReadsTheCodeAStringSpells(_NodeDecides):

    @backlog
    def test_a_top_level_name_the_code_reads_is_kept(self):
        self.assertEachModelBehavesAsTheProgramDoes({
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

    @backlog
    def test_text_a_fold_spells_is_read(self):
        self.assertEachModelBehavesAsTheProgramDoes({
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

    @backlog
    def test_each_spelling_of_the_function_constructor_is_read(self):
        self.assertEachModelBehavesAsTheProgramDoes({
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
            'the constructor of a generator function': (
                "var k = 1; var g = (function* () {}).constructor('k = 2; yield 1'); var it = g(); console.log(k);"
                " it.next(); console.log(k);"
            ),
            'the constructor of an async function': (
                "var k = 1; var g = (async function () {}).constructor('k = 2'); g(); console.log(k);"
            ),
        })

    @backlog
    def test_a_write_the_code_makes_takes_effect_when_the_code_runs(self):
        self.assertEachModelBehavesAsTheProgramDoes({
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
            'a function running eval code writing a var': (
                "var k = 1; function run() { eval('k = 2'); } run(); console.log(k);"
            ),
            'a function running a body writing a var': (
                "var k = 1; function run() { Function('k = 2')(); } run(); console.log(k);"
            ),
        })

    @backlog
    def test_code_spelled_inside_the_code_keeps_its_role(self):
        self.assertEachModelBehavesAsTheProgramDoes({
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

    @backlog
    def test_global_code_a_body_runs_finds_the_global_past_a_parameter_of_the_same_name(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'a body built in a body, reading': (
                "var k = 5; console.log(Function('k', 'return Function(\"return k\")()')(0));"
            ),
            'a body built in a stored body, reading': (
                "var k = 5; var g = new Function('k', 'return Function(\"return k\")()'); console.log(g(0));"
            ),
            'a body built in a body, writing': (
                "var k = 1; Function('k', 'Function(\"k = 2\")()')(0); console.log(k);"
            ),
            'a body built in a default of a parameter, writing': (
                "var k = 1; Function('a = Function(\"k = 2\")(), k', 'return a')(); console.log(k);"
            ),
            'a string timer in a body, writing': (
                "var k = 1; Function('k', 'setTimeout(\"k = 2\", 0)')(0); setTimeout(function () { console.log(k); }, 10);"
            ),
        })

    @backlog
    def test_global_code_spelled_inside_eval_code_finds_the_global_past_a_local(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'a body built in an eval, beside a var of the same name': (
                "var k = 1; function f() { var k = 0; eval('\"use strict\"; Function(\"k = 2\")()'); return k; }"
                " console.log(f(), k);"
            ),
            'a body built in an eval, beside a let of the same name': (
                "let k = 1; function f() { let k = 0; eval('\"use strict\"; Function(\"k = 2\")()'); return k; }"
                " console.log(f(), k);"
            ),
        })

    @backlog
    def test_a_function_constructor_behind_a_chain_of_aliases_is_read(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'four names': (
                "var k = 1; var A = Function, B = A, C = B, D = C; var f = new D('a', 'k = a; return a');"
                " console.log(f(5), k);"
            ),
        })

    @backlog
    def test_a_name_holding_the_global_object_hands_the_code_every_global(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'a body reading a global through a name holding this': (
                "var k = 5; var G = this; var g = new Function('a', 'return a + G.k'); console.log(g(1));"
            ),
            'a body writing a global through a name holding globalThis': (
                "var k = 5; var G = globalThis; var g = new Function('v', 'G.k = v'); g(1); console.log(k);"
            ),
        })

    @backlog
    def test_a_spelled_direct_eval_runs_in_its_function(self):
        self.assertEachModelBehavesAsTheProgramDoes({
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

    @backlog
    def test_a_name_the_code_reaches_through_the_global_object_is_kept(self):
        self.assertEachModelBehavesAsTheProgramDoes({
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

    @backlog
    def test_a_write_the_code_makes_through_the_global_object_is_kept(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'a body assigning onto the global object': (
                "var k = 1; var g = new Function('v', 'Object.assign(globalThis, { k: v })'); g(2); console.log(k);"
            ),
            'a body defining a property of the global object': (
                "var k = 1; var g = new Function('v', 'Object.defineProperty(globalThis, \"k\", { value: v })'); g(2);"
                " console.log(k);"
            ),
            'a body setting a property of the global object': (
                "var k = 1; var g = new Function('v', 'Reflect.set(globalThis, \"k\", v)'); g(2); console.log(k);"
            ),
            'a body writing the global object under a spelled key': (
                "var k = 1; var g = new Function('v', 'globalThis[\"k\"] = v'); g(2); console.log(k);"
            ),
            'a body writing through its own alias of the global object': (
                "var k = 1; var h = new Function('v', 'var g = globalThis; g.k = v'); h(2); console.log(k);"
            ),
            'an eval writing this.k at the top': (
                "var k = 1; eval('this.k = 2'); console.log(k);"
            ),
            'an eval writing this.k in a sloppy function': (
                "var k = 1; function f() { eval('this.k = 2'); } f(); console.log(k);"
            ),
            'a body writing every global named k': (
                "var k = 1; var g = new Function('v', 'for (var p in globalThis) if (p === \"k\") globalThis[p] = v;');"
                " g(2); console.log(k);"
            ),
            'a body replacing a method through Object.assign': (
                "var g = new Function('v', 'Object.assign(String.prototype, { charAt: function () { return v; } })');"
                " g('Z'); console.log('abc'.charAt(1));"
            ),
            'a body writing a global through a function it declares and calls': (
                "var k = 1; var g = new Function('v', 'function s() { k = v; } s()'); g(2); console.log(k);"
            ),
        })

    @backlog
    def test_a_global_property_the_code_reads_or_writes_is_kept(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'a body reading a global the file stores on the global object': (
                "globalThis.x = 5; var y = Function('return x')(); console.log(y);"
            ),
            'a body reading the stored property through globalThis': (
                "globalThis.x = 5; var g = Function('return globalThis.x'); console.log(g());"
            ),
            'a body writing a global the file stores on the global object': (
                "globalThis.x = 5; Function('x = 6')(); console.log(globalThis.x);"
            ),
            'a body reading a global property between two stores': (
                "globalThis.x = 5; var g = Function('return x'); console.log(g()); globalThis.x = 6; console.log(g());"
            ),
            'a string timer reading a global property': (
                "globalThis.x = 5; setTimeout('console.log(x)', 0);"
            ),
            'an eval reading a global property in a function': (
                "globalThis.x = 5; function f() { return eval('x'); } console.log(f());"
            ),
            'a stored body reading a global property': (
                "globalThis.x = 5; var g = new Function('a', 'return a + x'); console.log(g(1));"
            ),
            'a stored body listing the keys of the global object': (
                "globalThis.x = 5; var g = new Function('a', 'return Object.keys(globalThis).includes(a)');"
                " console.log(g('x'));"
            ),
            'a stored body walking the global object': (
                "globalThis.x = 5; var g = new Function('a', 'for (var p in globalThis) if (p === a) return 1; return 0');"
                " console.log(g('x'));"
            ),
            'a stored body handing its this to a call': (
                "globalThis.x = 5; var g = new Function('a', 'return typeof Object.getOwnPropertyDescriptor(this, a)');"
                " console.log(g('x'));"
            ),
            'eval code in a stored body reading a global property': (
                "globalThis.x = 5; var g = new Function('a', 'return eval(\"a + x\")'); console.log(g(1));"
            ),
            'a stored body reading a global property under a key it concatenates': (
                "globalThis.ab = 1; var g = new Function('n', 'return n + globalThis[\"a\" + \"b\"]');"
                " console.log([1, 2].map(g).join());"
            ),
        })

    def test_a_global_object_the_code_answers_is_read_through(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'read through': (
                "globalThis.x = 1; var g = Function('return this')(); console.log(g.x);"
            ),
            'written through': (
                "var k = 5; var g = Function('return this')(); g.k = 7; console.log(k);"
            ),
            'a stored body answering, read through': (
                "globalThis.x = 1; var f = new Function('return this'); console.log(f().x);"
            ),
            'a nested construction answering, read through': (
                "globalThis.x = 1; var g = Function('return (function () {}).constructor(\"return this\")()')();"
                " console.log(g.x);"
            ),
            'read through in a function': (
                "globalThis.x = 5; function f() { var g = Function('return this')(); return g.x; } console.log(f());"
            ),
            'a stored body answering, read through in a function': (
                "globalThis.x = 5; var h = new Function('return this'); function f() { var g = h(); return g.x; }"
                " console.log(f());"
            ),
            'stored by a body in a name of the file, written through': (
                "var k = 5; var g; Function('g = this')(); g.k = 7; console.log(k);"
            ),
        })

    @backlog
    def test_a_global_object_the_code_hands_back_or_looks_into_is_read_through(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'an eval answering the global object it chooses': (
                "globalThis.k = 1; var g = eval(process.argv.length > 99 ? 'this' : 'globalThis'); console.log(g.k);"
            ),
            'an eval in a function answering its this': (
                "globalThis.k = 1; function f() { return eval(process.argv.length > 99 ? '0' : 'this'); }"
                " console.log(f().k);"
            ),
            'a body answering the global object under a name of its own': (
                "globalThis.k = 1; var g = Function(process.argv.length > 99 ? 'return 0' : 'return this.globalThis')();"
                " console.log(g.k);"
            ),
            'a body answering the global object through valueOf': (
                "globalThis.k = 1; var g = Function(process.argv.length > 99 ? 'return 0' : 'return this.valueOf()')();"
                " console.log(g.k);"
            ),
            'a body testing a global property under a key it is handed': (
                "globalThis.x = 5; var g = new Function('n', 'return globalThis.hasOwnProperty(n)');"
                " console.log([0].map(function () { return g('x'); })[0]);"
            ),
        })

    def test_a_property_read_through_a_global_object_a_stored_body_answers_becomes_a_read_of_the_global(self):
        self.assertEachModelPrints({
            "globalThis.x = 1; var f = new Function('return this'); console.log(f().x);": (
                'globalThis.x = 1;\nconsole.log(x);'
            ),
        })

    @backlog
    def test_an_object_the_code_names_is_neither_folded_nor_removed(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'a body writing a property of an object': (
                "var o = { x: 1 }; var g = new Function('v', 'o.x = v'); g(7); console.log(o.x);"
            ),
            'a body writing an element of an array': (
                "var t = ['x', 'y']; var g = new Function('v', 't[0] = v'); g('z'); console.log(t[0]);"
            ),
            'a body reading an object the file reads': (
                "var t = { a: 'hi' }; console.log(t.a); var g = new Function('k', 'return t[k]'); console.log(g('a'));"
            ),
            'a string timer reading an object the file reads': (
                "var t = { a: 'hi' }; console.log(t.a); setTimeout('var q = t.a; console.log(q)', 0);"
            ),
            'an eval in a function writing a property of a global object': (
                "var o = { x: 1 }; function f(c) { if (c) eval('o.x = 7'); return o.x; } console.log(f(1));"
            ),
            'a body reading a namespace the file reads': (
                "var ns = {}; ns.a = 1; ns.b = 2; console.log(ns.a + ns.b);"
                " var g = new Function('x', 'return ns.a + x'); console.log(g(1));"
            ),
        })

    @backlog
    def test_a_declaration_moved_to_the_top_leaves_the_names_the_code_reads_alone(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'a local of a function called once': (
                "function main() { var k = [1, 2]; console.log(k.length); } main();"
                " var g = new Function('a', 'return typeof k'); console.log(g(0));"
            ),
            'a local of a body constructed and called in place': (
                "new Function('var k = [1]; console.log(k.length)')();"
                " var g = new Function('a', 'return typeof k'); console.log(g(0));"
            ),
        })

    @backlog
    def test_text_a_name_holds_is_read_where_the_file_also_reads_the_names_it_uses(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'an eval of a constant': (
                "var k = 1; var code = 'k = 2'; eval(code); console.log(k);"
            ),
            'an eval of a constant in a function': (
                "var k = 1; function f() { var code = 'k = 2; 0'; return eval(code); } f(); console.log(k);"
            ),
            'a string timer running a constant': (
                "var k = 1; var code = 'k = 2; var z = 0'; setTimeout(code, 0);"
                " setTimeout(function () { console.log(k); }, 10);"
            ),
            'a body held by a constant, writing': (
                "var k = 1; var body = 'k = a'; var g = new Function('a', body); g(2); console.log(k);"
            ),
            'a body held by a constant read twice': (
                "var k = 5; var s = 'return a + k; /* padding padding padding padding padding padding */';"
                " var add = new Function('a', s); var add2 = new Function('a', s); console.log(add(1), add2(2));"
            ),
            'a body held by a constant, reading a constant the file reads': (
                "var s = 'return a + k'; var k = 5; console.log(k); var g = new Function('a', s); console.log(g(1));"
            ),
            'a body held by a constant, reading an object the file reads': (
                "var s = 'return a + t.x'; var t = { x: 5 }; console.log(t.x); var g = new Function('a', s);"
                " console.log(g(1));"
            ),
        })

    @backlog
    def test_a_built_in_the_code_replaces_through_a_name_of_the_file_is_not_folded(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'a name holding String': (
                "var S = String; var p = new Function('v', 'S.prototype.charAt = function () { return v; }');"
                " p('x'); console.log('abc'.charAt(1));"
            ),
            'a name holding Math': (
                "var M = Math; var p = new Function('v', 'M.floor = function () { return v; }'); p(7);"
                " console.log(Math.floor(1.5));"
            ),
        })

    @backlog
    def test_a_built_in_the_code_replaces_is_not_taken_for_one_that_runs_nothing(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'a method the code replaces, called for nothing': (
                "var p = new Function('v', 'Math.max = function () { console.log(v); return 0; }'); p('x');"
                " var unused = Math.max(1, 2);"
            ),
            'a constructor the code replaces, read through a name of the file': (
                "var A = Array; var p = new Function('v', 'Array = function () { return [v]; }; return 0'); p('x');"
                " function make() { return A(2).length; } console.log(make());"
            ),
        })

    @backlog
    def test_a_built_in_the_code_replaces_is_not_folded(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'a body replacing a method of String.prototype': (
                "var p = new Function('v', 'String.prototype.charAt = function () { return v; }'); p('x');"
                " console.log('abc'.charAt(1));"
            ),
            'a body replacing atob': (
                "new Function('atob = function (s) { return s; }; return arguments.length')(); console.log(atob('aGk='));"
            ),
        })

    def test_a_method_every_function_has_that_the_code_replaces_is_not_folded(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'a body replacing Function.prototype.call': (
                "function add(a, b) { return a + b; }"
                " new Function('v', 'Function.prototype.call = function () { return v; }')('hijacked');"
                " console.log(add.call(null, 1, 2));"
            ),
            'a stored body replacing Function.prototype.apply': (
                "function add(a, b) { return a + b; }"
                " var h = new Function('v', 'Function.prototype.apply = function () { return v; }'); h('hijacked');"
                " console.log(add.apply(null, [1, 2]));"
            ),
            'a body replacing call through the prototype of a function': (
                "function add(a, b) { return a + b; }"
                " new Function('v', 'Object.getPrototypeOf(function () {}).call = function () { return v; }')('hijacked');"
                " console.log(add.call(null, 1, 2));"
            ),
            'a body replacing apply through __proto__': (
                "function add(a, b) { return a + b; }"
                " new Function('v', '(function () {}).__proto__.apply = function () { return v; }')('hijacked');"
                " console.log(add.apply(null, [1, 2]));"
            ),
            'a stored body replacing call through the prototype of a function': (
                "function add(a, b) { return a + b; }"
                " var h = new Function('v', 'Object.getPrototypeOf(function () {}).call = function () { return v; }');"
                " h('hijacked'); console.log(add.call(null, 1, 2));"
            ),
            'a stored body replacing apply through __proto__': (
                "function add(a, b) { return a + b; }"
                " var h = new Function('v', '(function () {}).__proto__.apply = function () { return v; }');"
                " h('hijacked'); console.log(add.apply(null, [1, 2]));"
            ),
            'a stored body replacing call, a parameter passed through call': (
                "function f(a) { return a + '!'; }"
                " var h = new Function('Object.getPrototypeOf(function () {}).call = function (t, v) { return this(v + \"Z\"); };');"
                " h(); console.log(f.call(null, 'x'));"
            ),
            'a stored body replacing call through __proto__, a parameter passed through call': (
                "function f(a) { return a + '!'; }"
                " var h = new Function('(function () {}).__proto__.call = function (t, v) { return this(v + \"Z\"); };');"
                " h(); console.log(f.call(null, 'x'));"
            ),
            'an eval replacing call, a parameter passed through call': (
                "function f(a) { return a + '!'; }"
                " eval('Object.getPrototypeOf(function () {}).call = function (t, v) { return this(v + \"Z\"); };');"
                " console.log(f.call(null, 'x'));"
            ),
            'a stored body replacing apply, a parameter passed through apply': (
                "function f(a) { return a + '!'; }"
                " var h = new Function('Object.getPrototypeOf(function () {}).apply = function (t, v) { return this(v[0] + \"Z\"); };');"
                " h(); console.log(f.apply(null, ['x']));"
            ),
        })

    @backlog
    def test_a_method_every_object_has_that_the_code_replaces_is_not_folded(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'a getter installed on Object.prototype': (
                "var h = new Function('Object.defineProperty(Object.prototype, \"q\", { get: function () { return 7; } })');"
                " h(); var o = {}; console.log(o.q);"
            ),
            'the array iterator replaced': (
                "var h = new Function('Array.prototype[Symbol.iterator] = function* () { yield 9; }');"
                " h(); var a = [1, 2]; console.log(Math.max(...a));"
            ),
            'Object.prototype.toString replaced': (
                "var h = new Function('Object.prototype.toString = function () { return \"T\"; }');"
                " h(); console.log('' + {});"
            ),
            'Object.prototype.valueOf replaced, then a product': (
                "var h = new Function('Object.prototype.valueOf = function () { return 3; }');"
                " h(); var o = {}; console.log(o * 2);"
            ),
            'a setter installed on Object.prototype, then a store': (
                "var log = [];"
                " var h = new Function('log', 'Object.defineProperty(Object.prototype, \"q\", { set: function (v) { log.push(v); } })');"
                " h(log); var o = {}; o.q = 4; console.log(log.length, o.q);"
            ),
        })

    def test_the_match_statics_the_code_reads_are_kept(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'a body reading RegExp.$1': (
                "var s = 'ab'.replace(/(a)/, 'x'); console.log(new Function('return RegExp.$1')());"
            ),
            'a body reading the match statics through a constructor': (
                "var s = 'ab'.replace(/(a)/, 'x'); console.log(new Function('return /z/.constructor.$1')());"
            ),
            'a stored body reading RegExp.$1': (
                "var s = 'ab'.replace(/(a)/, 'x'); var h = new Function('return RegExp.$1'); console.log(h());"
            ),
            'a stored body reading the match statics through a constructor': (
                "var s = 'ab'.replace(/(a)/, 'x'); var h = new Function('return /z/.constructor.$1'); console.log(h());"
            ),
        })

    def test_a_class_the_code_constructs_through_an_instance_is_kept(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'a body': (
                "class A { constructor(x) { this.x = x; } } var a = new A(1);"
                " console.log(a.x, new Function('o', 'return new o.constructor(5).x')(a));"
            ),
            'a stored body': (
                "class A { constructor(x) { this.x = x; } } var a = new A(1);"
                " var h = new Function('o', 'return new o.constructor(5).x'); console.log(a.x, h(a));"
            ),
        })

    def test_a_host_global_the_code_deletes_is_not_taken_for_present(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'a body': (
                "new Function('delete globalThis.Buffer')(); console.log(typeof Buffer);"
            ),
            'a stored body': (
                "var h = new Function('delete globalThis.Buffer'); h(); console.log(typeof Buffer);"
            ),
        }, environment='node')

    @backlog
    def test_a_function_the_code_converts_to_a_string_keeps_its_text(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'a body giving a function the file hands it a toString': (
                "function W(a) { return a + 1; } var g = [W]; Function('g', 'g[0].toString = function () { return \"F\"; };')(g);"
                " function f() { return String(W); } console.log(f());"
            ),
            'a stored body giving a function the file hands it a toString': (
                "function W(a) { return a + 1; } var h = new Function('g', 'g.toString = function () { return \"F\"; };'); h(W);"
                " console.log(String(W));"
            ),
            'a stored body handing a function to a call that converts it': (
                "function W(a) { return a + 1; }"
                " var h = new Function('f', 'Object.defineProperty(f, \"toString\", { value: function () { return \"D\"; } })');"
                " h(W); console.log(String(W));"
            ),
        })

    @backlog
    def test_a_function_the_code_calls_keeps_what_it_does(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'a function writing a global, called by a body a callback runs': (
                "var k = 1; function setK() { k = 2; } var g = new Function('a', 'setK(); return a');"
                " [0].forEach(g); console.log(k);"
            ),
            'a function whose value a body reads': (
                "var h; (function () { function inner() { console.log('ran'); return 42; } h = inner; inner(); })();"
                " var g = new Function('a', 'return h() + a'); console.log(g(1));"
            ),
            'the decoder of a string array a string timer calls': (
                "function _0x5e03(){var a=['300xyz','800abc','secret_value','another_string','500target'];"
                "_0x5e03=function(){return a;};return _0x5e03();}"
                "function _0x1169(p,q){p=p-0x1f0;var arr=_0x5e03();var r=arr[p];return r;}"
                "(function(a,t){"
                "var _0x221ff1=_0x1169,_0x5f2282={_0x2bb395:0x1f0,_0x56f5b5:0x1f1};"
                "var b=a();"
                "while(true){try{"
                "var c=parseInt(_0x221ff1(_0x5f2282._0x2bb395))/0x1"
                "+parseInt(_0x221ff1(_0x5f2282._0x56f5b5))/0x2;"
                "if(c===t)break;b.push(b.shift());}catch(e){b.push(b.shift());}}}(_0x5e03,0x2bc));"
                "var x=_0x1169(0x1f2);"
                "setTimeout('var t; console.log(_0x1169(0x1f3))', 0);"
                "console.log(x);"
            ),
            'a wrapper a body calls': (
                "function w() { return 'x'; }\nconsole.log(w());\n"
                "var g = new Function('a', 'return a + w()');\nconsole.log(g(1));"
            ),
            'a function the file evaluates, called by a body': (
                "function f() { return 'x' + 1; }\nconsole.log(f());\n"
                "var g = new Function('a', 'return a + f()');\nconsole.log(g(1));"
            ),
        })

    @backlog
    def test_a_host_function_the_code_calls_keeps_the_global_it_writes(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'called by a body': (
                "function stage() { result = 0; new Function('a', 'hostRun(a)')(1); return result; } console.log(stage());"
            ),
            'called by eval code': (
                "function stage() { result = 0; eval('hostRun(1)'); return result; } console.log(stage());"
            ),
        }, host=_A_HOST_FUNCTION_WRITING_RESULT)

    @backlog
    def test_a_write_eval_code_leaves_to_a_later_run_is_not_one_where_the_eval_stands(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'a closure writing a var the eval declares': (
                "function f() { var k; var r = eval('var k; globalThis.g = function () { k = 2 }; 0'); k = 1; g();"
                " return k + r; } console.log(f());"
            ),
            'a field initializer writing a local': (
                "function f() { var k; var r = eval('var C = class { x = (k = 2) }; 0'); k = 1; new C();"
                " return k + r; } console.log(f());"
            ),
        })

    @backlog
    def test_code_this_analysis_cannot_read_or_that_opens_the_world_keeps_every_name(self):
        self.assertEachModelBehavesAsTheProgramDoes({
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

    @backlog
    def test_a_pass_asking_about_one_name_sees_the_code_that_names_it(self):
        self.assertEachModelBehavesAsTheProgramDoes({
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

    @backlog
    def test_the_code_reads_what_runs_before_it(self):
        self.assertEachModelBehavesAsTheProgramDoes({
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
        self.assertEachModelBehavesAsTheProgramDoes({
            'a body answering the global object': (
                "var junk = 1; var g = Function('return this'); console.log(typeof g());"
            ),
            'a body beside a call of a built-in': (
                "var g = new Function('a', 'return a'); console.log('abc'.charAt(1), g(2));"
            ),
            'a body whose parameter has the name of a global': (
                "var k = 5; var id = new Function('k', 'return k'); console.log(id(1));"
            ),
            'an eval declaring a var beside a call of a built-in': (
                "eval('var z = 1'); console.log('abc'.charAt(1), z);"
            ),
            'a body built without new beside a call of a built-in': (
                "var g = Function('return 1'); console.log('abc'.charAt(1), g());"
            ),
        })

    def test_a_commonjs_var_is_not_a_name_the_code_finds(self):
        source = "var k = 5; var add = new Function('a', 'return a + k'); console.log(add(1));"
        self.assertEqual(
            {_model(strict): behavior(source.encode('utf8') | djs(commonjs=True, strict=strict) | str) for strict in _EITHER_MODEL},
            {_model(strict): behavior(source) for strict in _EITHER_MODEL},
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestEitherModelReadsTheTextAHelperHandsToTheCodeItRuns(_NodeDecides):

    @backlog
    def test_a_helper_handing_its_parameter_on_keeps_the_name_the_text_reads(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'a helper constructing from its parameter': (
                "function mk(src) { return new Function('a', src); } var k = 5; console.log(mk('return a + k')(1));"
            ),
            'a helper scheduling its parameter': (
                "var k = 1; function later(s) { setTimeout(s, 0); } later('console.log(k)');"
            ),
            'a helper scheduling its parameter and answering the timer': (
                "var k = 1; function later(s) { return setTimeout(s, 0); } later('console.log(k)');"
            ),
            'two helpers handing the text on': (
                "function a(s) { return b(s); } function b(t) { return Function(t); } var k = 5; console.log(a('return k')());"
            ),
            'a helper held by a var': (
                "var mk = function (src) { return new Function(src); }; var k = 5; console.log(mk('return k')());"
            ),
            'a helper whose parameter defaults to the text': (
                "var k = 5; function mk(src = 'return k') { return Function(src); } console.log(mk()());"
            ),
            'a helper called through a second name': (
                "function mk(src) { return Function(src); } var m = mk; var k = 5; console.log(m('return k')());"
            ),
            'a helper aliased twice': (
                "function mk(src) { return Function(src); } var m = mk; var n = m; var k = 5; console.log(n('return k')());"
            ),
            'a helper called through call': (
                "function mk(src) { return Function(src); } var k = 5; console.log(mk.call(null, 'return k')());"
            ),
            'a helper called through apply': (
                "function mk(src) { return Function(src); } var k = 5; console.log(mk.apply(null, ['return k'])());"
            ),
            'a helper invoked where it is written': (
                "var k = 5; console.log((function (src) { return Function(src); })('return k')());"
            ),
            'a helper in a table': (
                "var o = { mk: function (src) { return Function(src); } }; var k = 5; console.log(o.mk('return k')());"
            ),
            'a helper in a table under a computed key': (
                "var o = { mk: function (src) { return Function(src); } }; var key = 'mk'; var k = 5;"
                " console.log(o[key]('return k')());"
            ),
            'a helper held by a named function expression calling itself': (
                "var k = 5; var mk = function m(src, n) { return n ? m(src, n - 1) : Function(src); };"
                " console.log(mk('return k', 2)());"
            ),
            'a helper declared in a block': (
                "{ function mk(src) { return Function(src); } } var k = 5; console.log(mk('return k')());"
            ),
            'a helper a block declares, called after the block': (
                "{ function mk(src) { return Function(src); } } var k = 5; console.log(mk('return k')(), mk('return k + 1')());"
            ),
            'a helper called through the global object': (
                "function mk(src) { return Function(src); } var k = 5; console.log(globalThis.mk('return k')());"
            ),
            'a helper called through a name holding the global object': (
                "function mk(src) { return Function(src); } var G = globalThis; var k = 5; console.log(G.mk('return k')());"
            ),
            'a helper a class constructor holds': (
                "var k = 5; class H { constructor(src) { this.f = Function(src); } } console.log(new H('return k').f());"
            ),
            'a helper a subclass constructor reaches through super': (
                "var k = 5; class H { constructor(src) { this.f = Function(src); } }"
                " class G extends H { constructor(s) { super(s); } } console.log(new G('return k').f());"
            ),
            'a helper running its parameter as a body, writing a var': (
                "var k = 1; function run(s) { Function(s)(); } run('k = 2'); console.log(k);"
            ),
            'a helper argument a fold spells': (
                "function mk(src) { return new Function(src); } var k = 5; console.log(mk(atob('cmV0dXJuIGs='))());"
            ),
        })

    def test_a_helper_handed_a_text_it_cannot_read_or_a_text_it_replaces_keeps_every_name(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'a helper called with an unreadable text and a readable one': (
                "var k = 5; function mk(src) { return Function(src); }"
                " console.log(mk('return k')(), mk('return ' + process.argv.length * 0)());"
            ),
            'a helper whose parameter is written first': (
                "var k = 5; function mk(src) { src = 'return 7'; return Function(src); } console.log(mk('return k')(), k);"
            ),
        })

    @backlog
    def test_each_call_of_a_helper_is_read_as_its_own_pairing_of_texts(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'one call of a one-text helper': (
                "var k1 = 1; function mk(b) { return new Function('a', b); } console.log(mk('return a + k1')(0));"
            ),
            'four calls of a two-text helper': (
                "var k1 = 1, k2 = 2, k3 = 3, k4 = 4;"
                " function mk(p, b) { return new Function(p, b); }"
                " console.log(mk('a', 'return a + k1')(0), mk('b', 'return b + k2')(0), mk('c', 'return c + k3')(0),"
                " mk('d', 'return d + k4')(0));"
            ),
            'five calls of a two-text helper': (
                "var k1 = 1, k2 = 2, k3 = 3, k4 = 4, k5 = 5;"
                " function mk(p, b) { return new Function(p, b); }"
                " console.log(mk('a', 'return a + k1')(0), mk('b', 'return b + k2')(0), mk('c', 'return c + k3')(0),"
                " mk('d', 'return d + k4')(0), mk('e', 'return e + k5')(0));"
            ),
            'six calls of a two-text helper': (
                "var k1 = 1, k2 = 2, k3 = 3, k4 = 4, k5 = 5, k6 = 6;"
                " function mk(p, b) { return new Function(p, b); }"
                " console.log(mk('a', 'return a + k1')(0), mk('b', 'return b + k2')(0), mk('c', 'return c + k3')(0),"
                " mk('d', 'return d + k4')(0), mk('e', 'return e + k5')(0), mk('f', 'return f + k6')(0));"
            ),
            'a two-text helper handing both texts to a second': (
                "var k = 5; function inner(p, b) { return new Function(p, b); } function outer(p, b) { return inner(p, b); }"
                " console.log(outer('a', 'return a + k')(1), outer('b', 'return b * k')(2));"
            ),
            'a helper whose texts are a choice in each call': (
                "var k = 5, j = 6; function mk(p, b) { return new Function(p, b); }"
                " var c = process.argv.length > 99; console.log(mk(c ? 'x' : 'a', c ? 'return x' : 'return a + k')(1),"
                " mk('a', 'return a + j')(1));"
            ),
            'a helper with one text in place and one handed on': (
                "var k = 5; function mk(b) { return new Function('a', b); } console.log(mk('return a + k')(1), mk('return a')(2));"
            ),
            'a helper given a parameter text and a default body': (
                "var k = 5; function mk(p, b = 'return ' + 'k') { return new Function(p, b); } console.log(mk('a')(1));"
            ),
            'a helper given a default body as a literal': (
                "var k = 5; function mk(p, b = 'return k') { return new Function(p, b); }"
                " console.log(mk('a')(1), mk('a', 'return a')(2));"
            ),
            'two calls whose texts paired across the calls would write a global': (
                "function mk(p, b) { return new Function(p, b); }"
                " var set = mk('window, k', 'window[k] = 1'); var get = mk('x', 'return x');"
                " var o = {}; set(o, 'q'); console.log('abc'.charAt(1), get(2), o.q);"
            ),
            'the same two constructions written out': (
                "var set = new Function('window, k', 'window[k] = 1'); var get = new Function('x', 'return x');"
                " var o = {}; set(o, 'q'); console.log('abc'.charAt(1), get(2), o.q);"
            ),
            'two calls whose texts paired across the calls are harmless': (
                "function mk(p, b) { return new Function(p, b); }"
                " var set = mk('w, k', 'w[k] = 1'); var get = mk('x', 'return x');"
                " var o = {}; set(o, 'q'); console.log('abc'.charAt(1), get(2), o.q);"
            ),
        })

    def test_a_helper_running_its_parameter_as_eval_code_is_left_to_the_eval(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'reading a var': (
                "function run(s) { return eval(s); } var k = 5; console.log(run('k + 1'));"
            ),
            'reading its arguments': (
                "function run(s) { return eval(s); } console.log(run('arguments.length'), run('arguments[0].length'));"
            ),
            'declaring undefined': (
                "function run(s) { eval(s); return undefined; } console.log(run('var undefined = 4'));"
            ),
        })

    def test_a_function_under_a_second_name_is_called_as_before(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'called through both names': (
                "function f(a) { return a + 1; } var g = f; console.log(g(1), f(2));"
            ),
            'handed to map under the second name': (
                "function f(a) { return a * 2; } var g = f; console.log([1, 2].map(g).join(), g(5));"
            ),
            'called without an argument under the second name': (
                "function f(a) { return typeof a; } var g = f; console.log(g('x'), g());"
            ),
            'called through a name of a name': (
                "function f(a) { return a + 1; } var g = f; var h = g; console.log(h(1), h(1));"
            ),
            'stored on the global object under the second name': (
                "function f(a) { return a + 1; } var g = f; globalThis.q = g; console.log(g(1), q(2));"
            ),
            'a second name reassigned': (
                "function f(a) { return a + 1; } function k(a) { return a * 9; } var g = f; console.log(g(1)); g = k;"
                " console.log(g(2));"
            ),
            'a second name a string timer calls': (
                "function f(a) { return a + 1; } var g = f; console.log(g(1)); setTimeout('console.log(g(10))', 0);"
            ),
            'a second name called with one constant': (
                "function f(a, b) { return a + b; } var g = f; console.log(g(1, 2), g(1, 3));"
            ),
        })

    def test_a_table_under_a_second_name_is_no_second_name_of_its_function(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'an entry named call': (
                "var t = { call: function (a) { if (!a) { a = function () { return 'default'; }; } return a(); } };"
                " var t2 = t; console.log(t2.call(function () { return 'passed'; }));"
                " console.log(t2.call(function () { return 'again'; }));"
            ),
        })


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestEitherModelReadsAChoiceBetweenTextsAsEachText(_NodeDecides):

    @backlog
    def test_each_text_of_a_choice_is_read(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'an eval choosing between two texts': (
                "var x = 1; function f(c) { if (c) eval(process.argv.length > 99 ? '' : 'var x = 4'); return x; }"
                " console.log(f(1), f(0));"
            ),
            'a constant holding a choice': (
                "var k = 5; var code = process.argv.length > 99 ? 'return 0' : 'return k'; console.log(Function(code)());"
            ),
            'a nested choice': (
                "var k = 1; eval(process.argv.length > 99 ? '' : process.argv.length > 98 ? 'k = 3' : 'k = 2');"
                " console.log(k);"
            ),
            'a choice with one text it cannot read': (
                "var k = 5; console.log(Function(process.argv.length > 99 ? 'return ' + process.argv.length : 'return k')());"
            ),
            'an or between an unknown and a text': (
                "var k = 5; console.log(Function(process.argv[99] || 'return k')());"
            ),
            'an and of a test and a text': (
                "var k = 5; console.log(Function(process.argv.length > 0 && 'return k')());"
            ),
            'a chosen parameter text': (
                "var k = 5; console.log(Function(process.argv.length > 99 ? 'a' : 'b', 'return k')(1));"
            ),
            'a chosen timer text': (
                "let k = 1; setTimeout(process.argv.length > 99 ? '' : 'console.log(k)', 0);"
            ),
            'a choice with a text that reads the global object under a computed key': (
                "var k = 5; var n = 'k';"
                " console.log(Function('n', process.argv.length > 99 ? 'return globalThis[n]' : 'return k')(n));"
            ),
            'a choice writing a built-in': (
                "eval(process.argv.length > 99 ? '' : 'String.prototype.charAt = function () { return \"Z\"; }');"
                " console.log('abc'.charAt(1));"
            ),
            'a choice under a test that compares a string': (
                "var k = 5; eval(String(process.argv.length > 99) === 'true' ? '' : 'console.log(k)');"
            ),
            'the constructor of a constructor running a chosen text that replaces join': (
                "var code = process.argv.length > 99 ? '' : 'Array.prototype.join = function () { return \"J\"; };';"
                " [].constructor.constructor(code)(); console.log(-[5]);"
            ),
            'an optional call of eval choosing between two texts': (
                "var s = 'ab'; eval?.(process.argv.length > 99 ? '' : 's = \"abc\"'); console.log(s.length);"
            ),
            'a choice a fold spells, read in place': (
                "var k = 5; console.log(Function(process.argv.length > 99 ? '' : atob('cmV0dXJuIGs='))());"
            ),
            'an eval choice a fold spells, writing': (
                "var k = 1; eval(process.argv.length > 99 ? '' : atob('ayA9IDI=')); console.log(k);"
            ),
            'a constant holding a choice a fold spells': (
                "var k = 5; var code = process.argv.length > 99 ? '' : atob('cmV0dXJuIGs='); console.log(Function(code)());"
            ),
            'a stored body whose chosen text a fold spells': (
                "var k = 5; var g = new Function(process.argv.length > 99 ? 'return 0' : atob('cmV0dXJuIGs='));"
                " console.log(g());"
            ),
        })

    @backlog
    def test_a_function_a_chosen_text_calls_is_kept(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'a function the file declares': (
                "function f() { return 'x'; }\nconsole.log(f());\n"
                "Function(process.argv.length > 99 ? '' : 'console.log(f())')();"
            ),
            'a function a block declares': (
                "{ function f() { return 'x'; } console.log(f()); }\n"
                "Function(process.argv.length > 99 ? '' : 'console.log(f())')();"
            ),
        })

    def test_a_text_held_by_a_name_its_own_default_names_is_read(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'an eval': "var code = code || 'console.log(1)'; eval(code);",
            'two texts naming each other in a choice': "var a = 1 ? b : 'x = 1'; var b = 1 ? a : 'y = 2'; eval(a);",
            'a construction': "var body = body || 'return 1'; console.log(Function(body)());",
            'a string timer': "var t = t || 'console.log(1)'; setTimeout(t, 0);",
        })


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestTheSuspectingModelReadsNoTextANameHoldsThatOtherCodeMayReplace(_NodeDecides):

    def test_a_text_other_code_may_replace_is_not_read_as_the_declared_one(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'code in a string replacing the text': (
                "let x = 5; var code = 'console.log(1)';"
                " eval(process.argv.length > 99 ? '' : \"code = 'console.log(x)'\"); eval(code);"
            ),
            'a stored body replacing the text': (
                "var k = 5; var s = '0'; [1].forEach(new Function('s = \"k = 9\"')); eval(s); console.log(k);"
            ),
            'a store on the global object under a key only the run knows': (
                "let x = 5; var code = 'console.log(1)'; var k = process.argv.length > 99 ? 'zzz' : 'code';"
                " globalThis[k] = 'console.log(x)'; eval(code);"
            ),
            'a text replacing itself in a loop': (
                "let x = 5; var p = \"p = 'console.log(x)'\"; for (var i = 0; i < 2; i++) eval(p);"
            ),
            'a constructed body replacing the text when called later': (
                "let x = 5; var code = 'console.log(1)';"
                " var g = new Function(process.argv.length > 99 ? '' : \"code = 'console.log(x)'\"); g(); eval(code);"
            ),
            'a store on the this of the script under a key only the run knows': (
                "let x = 5; var code = 'console.log(1)'; var k = process.argv.length > 99 ? 'zzz' : 'code';"
                " this[k] = 'console.log(x)'; eval(code);"
            ),
            'code in a string a function runs replacing the text': (
                "let x = 5; var code = 'console.log(1)';"
                " function g() { eval(process.argv.length > 99 ? '' : \"code = 'console.log(x)'\"); } g(); eval(code);"
            ),
            'a constructed body replacing the text of a let': (
                "let x = 5; let code = 'console.log(1)';"
                " Function(process.argv.length > 99 ? '' : \"code = 'console.log(x)'\")(); eval(code);"
            ),
            'a loader the stage calls filling a name the stage declares': (
                "var k = 5; function load() { next = 'console.log(k)'; } eval(\"var next = ''; load(); eval(next);\");"
            ),
            'a function the stage calls replacing a text the stage declares': (
                "let x = 5; function f() { code = 'console.log(x)'; }"
                " eval(\"var code = 'console.log(1)'; f(); eval(code);\");"
            ),
            'a loader the stage calls storing under a key only the run knows': (
                "let x = 5; function f(k) { globalThis[k] = 'console.log(x)'; }"
                " eval(\"var next = ''; f(process.argv.length > 99 ? 'zzz' : 'next'); eval(next);\");"
            ),
            'an inner stage declaring the name of the stage again': (
                "let x = 5; eval(\"var next = ''; eval(\\\"var next = 'console.log(x)'\\\"); eval(next);\");"
            ),
            'a for-in head assigning each key to the name it declares': (
                "let x = 5; var o = {'console.log(x)': 1}; for (var code = 'console.log(1)' in o) {} eval(code);"
            ),
            'a loader filling the name a timer declares that a constructed body sets': (
                "var k = 5; function load() { next = 'console.log(k)'; }"
                " [1].forEach(new Function(\"setTimeout(\\\"var next = ''; load(); eval(next);\\\", 0)\"));"
            ),
            'a loader filling the name a timer declares that a function of a timer sets': (
                "var k = 5; function load() { next = 'console.log(k)'; }"
                " setTimeout(\"function g() { setTimeout(\\\"var next = ''; load(); eval(next);\\\", 0); } g();\", 0);"
            ),
            'a loader filling the name a timer declares that strict code in a string sets': (
                "var k = 5; function load() { next = 'console.log(k)'; }"
                " eval(\"'use strict'; setTimeout(\\\"var next = ''; load(); eval(next);\\\", 0)\");"
            ),
            'a loader filling the name a timer declares that code in a string sets beside a local of that name': (
                "var k = 5; function load() { next = 'console.log(k)'; }"
                " function f(next) { return eval(\"setTimeout(\\\"var next = ''; load(); eval(next);\\\", 0); next\"); }"
                ' console.log(f(1));'
            ),
        }, models=_THE_SUSPECTING_MODEL)

    @opportunity
    def test_a_text_is_read_beside_code_in_a_string_no_call_runs(self):
        self.assertEachModelPrints({
            "var k = 5; var code = 'console.log(k)'; function never(x) { return eval(x); } eval(code);": (
                'console.log(5);'
            ),
        }, models=_THE_SUSPECTING_MODEL)

    @opportunity
    def test_a_text_is_read_beside_a_string_timer_that_runs_after_it(self):
        self.assertEachModelPrints({
            "var k = 5; var code = 'console.log(k)'; function never(x) { setTimeout(x, 0); } eval(code);": (
                'console.log(5);'
            ),
        }, models=_THE_SUSPECTING_MODEL)

    @backlog
    def test_a_text_held_where_its_eval_runs_writes_what_it_spells(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'a local of a function writing a global': (
                "var k = 5; function f() { var p = 'k = 7'; eval(p); return k; } console.log(f());"
            ),
        }, models=_THE_SUSPECTING_MODEL)

    @backlog
    def test_a_text_nothing_else_writes_is_still_read(self):
        self.assertEachModelPrints({
            "(function () { var p = 'console.log(1)'; eval(p); })(); console.log(String.fromCharCode(72, 105));": (
                "(function() {\n  var p = 'console.log(1)';\n  eval(p);\n})();\nconsole.log('Hi');"
            ),
            (
                "function f() { var k = 5; var code = 'k = 7'; eval(code); return k; }"
                ' console.log(f(), String.fromCharCode(72, 105));'
            ): (
                "function f() {\n  var k = 5;\n  var code = 'k = 7';\n  eval(code);\n  return k;\n}\nconsole.log(f(), 'Hi');"
            ),
            "var p = 'console.log(p.length)'; eval(p);": 'console.log(21);',
            "const k = 5; const code = 'console.log(k)'; function never(x) { return eval(x); } eval(code);": (
                'console.log(5);'
            ),
            (
                "let x = 5; var code = 'console.log(x)'; var other = 1;"
                " eval(process.argv.length > 99 ? '' : 'other = 2'); eval(code);"
            ): "var other = 1;\neval(process.argv.length > 99 ? '' : 'other = 2');\nconsole.log(5);",
            "let x = 5; eval(\"var p = 'console.log(x)'; eval(p);\");": 'console.log(5);',
        }, models=_THE_SUSPECTING_MODEL)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestEitherModelRunsATextANameTheHostKeepsHoldsAsTheProgramDoes(_NodeDecides):

    @backlog
    def test_a_text_held_by_a_name_a_window_keeps_runs_as_the_program_runs_it(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'the name of a window run by eval': "var key = 'secret'; var name = 'console.log(key)'; eval(name);",
            'the status of a window run by eval': "var k = 5; var status = 'k = 7'; eval(status); console.log(k);",
            'the name of a window run by a constructed body': (
                "var key = 'secret'; var name = 'console.log(key)'; new Function(name)();"
            ),
            'the name of a window run by a timer': "let x = 5; var name = 'console.log(x)'; setTimeout(name, 0);",
        })


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestEitherModelReadsTheTextAFoldWouldWrite(_NodeDecides):

    @backlog
    def test_a_text_a_fold_would_write_runs_as_the_program_runs_it(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'a decoded text replacing the decoder before the next one': (
                "eval(atob('YXRvYiA9IGZ1bmN0aW9uICgpIHsgcmV0dXJuICJjb25zb2xlLmxvZygyKSI7IH07'));"
                " eval(atob('Y29uc29sZS5sb2coMSk='));"
            ),
            'a decoded text replacing join before a joined one': (
                'eval(atob('
                "'QXJyYXkucHJvdG90eXBlLmpvaW4gPSBmdW5jdGlvbiAoKSB7IHJldHVybiAiY29uc29sZS5sb2coMikiOyB9Ow=='"
                ")); eval(['console.log(1)'].join(''));"
            ),
            'a decoded text writing a var': (
                "var k = 5; eval(atob('ayA9IDc=')); console.log(k);"
            ),
            'a joined text a helper runs writing a var': (
                "var k = 5; function run(code) { return new Function(code)(); } run(['k = ', '7'].join('')); console.log(k);"
            ),
            'a decoded text and a sum': (
                "var k = 5; eval(atob('ayA9IA==') + (3 + 4)); console.log(k);"
            ),
            'two decoded halves': (
                "var k = 5; eval(atob('ayA9') + atob('IDc=')); console.log(k);"
            ),
            'character codes and a sum': (
                'var k = 5; eval(String.fromCharCode(107, 32, 61, 32, 48 + 7)); console.log(k);'
            ),
            'a template and a sum': (
                'var k = 5; eval(`k = ${3 + 4}`); console.log(k);'
            ),
        })

    def test_a_text_the_fold_gate_refuses_leaves_the_folds_of_the_run_that_assumes_writes_followed(self):
        self.assertEachModelPrints({
            "atob = function () { return 'q = 2'; }; eval(atob('cSA9IDE=')); console.log([][(false + [])[0] + 'oo']);": (
                "atob = function() {\n  return 'q = 2';\n};\neval(atob('cSA9IDE='));\nconsole.log(void 0);"
            ),
        }, models=(False,))

    def test_a_text_holding_a_number_the_engine_approximates_runs_as_the_program_runs_it(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'a power': "var k = 5; eval('k = ' + 2 ** 0.5); console.log(k > 1);",
            'Math.pow': "var k = 5; eval('k = ' + Math.pow(2, 0.5)); console.log(k > 1);",
            'a power in a template': 'var k = 5; eval(`k = ${2 ** 0.5}`); console.log(k > 1);',
        })

    def test_a_buffer_converted_to_text_runs_as_the_program_runs_it(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'hex': (
                "var k = 5; try { eval(Buffer.from('k = 7').toString('hex')); } catch (e) { console.log(e.name); }"
                ' console.log(k);'
            ),
            'base64': (
                "var k = 5; try { eval(Buffer.from('k = 7').toString('base64')); } catch (e) { console.log(e.name); }"
                ' console.log(k);'
            ),
            'the default encoding': "var k = 5; eval(Buffer.from('k = 7').toString()); console.log(k);",
        }, environment='node')

    def test_the_suspecting_model_reads_no_text_decoded_with_a_built_in_replaced_without_its_name(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'join through the prototype of an array': (
                "Object.getPrototypeOf([]).join = function () { return 'console.log(2)'; };"
                " eval(['console.log(1)'].join(''));"
            ),
            'join through the constructor of an array': (
                "[].constructor.prototype.join = function () { return 'console.log(2)'; };"
                " eval(['console.log(1)'].join(''));"
            ),
            'fromCharCode through the constructor of a string': (
                "''.constructor.fromCharCode = function () { return 'console.log(2)'; };"
                ' eval(String.fromCharCode(99, 111, 110, 115, 111, 108, 101, 46, 108, 111, 103, 40, 49, 41));'
            ),
        }, models=_THE_SUSPECTING_MODEL)


class TestTheTextsOfAProgramAreReadInTimeThatGrowsWithTheProgram(TestBase):

    def test_the_calls_of_a_two_text_helper(self):
        def program(count: int) -> str:
            calls = ''.join(F"var k{i} = {i}; mk('a{i}', 'return a{i} + k{i}');" for i in range(count))
            return F'function mk(p, b) {{ return new Function(p, b); }} {calls}'
        _assert_the_deobfuscation_takes_time_that_grows_with_the_program(self, program(400), program(1600))

    def test_a_chain_of_choices_sharing_names(self):
        def program(depth: int) -> str:
            chain = ''.join(F'var a{i} = c ? a{i + 1} : a{i + 1};' for i in range(depth))
            return F"var c = process.argv.length > 99; {chain} var a{depth} = 'x = 1'; eval(a0);"
        _assert_the_deobfuscation_takes_time_that_grows_with_the_program(self, program(320), program(1280))

    @a_property_of_the_pin_itself
    def test_the_texts_a_helper_is_handed_once_a_fold_spells_them(self):
        def program(count: int) -> str:
            calls = ''.join(F"out.push(run(['retu', 'rn {i}'].join('')));" for i in range(count))
            return F'var out = []; function run(code) {{ return new Function(code)(); }} {calls} console.log(out.length);'
        _assert_the_deobfuscation_takes_time_that_grows_with_the_program(self, program(100), program(400))

    def test_a_string_longer_than_any_the_engine_folds_is_not_built(self):
        source = "eval(['/*', 'x'.repeat(40000000), '*/ console.log(1)'].join(''));"
        for strict in _EITHER_MODEL:
            with self.subTest(_model(strict)):
                self.assertLess(_fastest_deobfuscation(source, strict), 1.0)
                self.assertIn("'x'.repeat(40000000)", _deobfuscated(source, strict))

    @todo
    def test_a_string_longer_than_any_the_engine_folds_is_not_built_from_shorter_ones(self):
        sources = (
            "eval(['/*', 'a', 'a', '*/ console.log(1)'].join('x'.repeat(999999)));",
            "eval('/*' + 'aa'.replaceAll('a', 'x'.repeat(999999)) + '*/ console.log(1)');",
            "eval('/*' + 'x'.repeat(999).replace('x', \"$'\".repeat(9999)) + '*/ console.log(1)');",
        )
        for source in sources:
            for strict in _EITHER_MODEL:
                with self.subTest(source=source, model=_model(strict)):
                    self.assertLess(len(_deobfuscated(source, strict)), 2_000_000)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestTheSuspectingModelReadsNoCodeThroughWhichTheGlobalObjectEscapes(_NodeDecides):

    def test_a_name_the_code_reads_through_a_global_object_it_finds_is_kept(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'a body answering the global object': (
                "var k = 5; var g = new Function('a', 'var G = Function(\"return this\")(); return a + G.k');"
                " console.log(g(1));"
            ),
            'a nested function answering the global object': (
                "var k = 5; var g = new Function('a', 'var G = (function () { return this; })(); return a + G.k');"
                " console.log(g(1));"
            ),
            'a stored body answering the global object': (
                "var k = 5; var g = new Function('var f = Function(\"return this\"); return f().k'); console.log(g());"
            ),
            'a walk of its this': (
                "var k = 5; var g = new Function('for (var p in this) if (p === \"k\") return this[p]; return 0');"
                " console.log(g());"
            ),
            'its this read under a computed key': (
                "var k = 5; var g = new Function('n', 'return this[n]'); console.log(g('k'));"
            ),
            'a host alias read under a computed key': (
                "var k = 5; var g = new Function('n', 'var w = typeof window === \"object\" ? window : globalThis;"
                " return w[n]'); console.log(g('k'));"
            ),
            'Reflect.get of its this': (
                "var k = 5; var g = new Function('n', 'return Reflect.get(this, n)'); console.log(g('k'));"
            ),
            'a nested function reading its this under a computed key': (
                "globalThis.x = 5; var g = new Function('a', 'return (function () { return this[a]; })()');"
                " console.log(g('x'));"
            ),
            'the global object under a name of its own, read under a computed key': (
                "var k = 5; console.log(Function('n', 'return globalThis.globalThis[n]')('k'));"
            ),
            'the global object under a name of its own, written under a computed key': (
                "var k = 5; Function('n', 'globalThis.globalThis[n] = 7')('k'); console.log(k);"
            ),
            'the global object under a name of its own, walked by a string timer': (
                "var k = 5; setTimeout('var g = global.global; for (var p in g) if (p === \"k\") console.log(g[p]);', 0);"
            ),
            'the global object valueOf answers, read under a computed key': (
                "var k = 5; console.log(Function('n', 'return globalThis.valueOf()[n]')('k'));"
            ),
        }, models=_THE_SUSPECTING_MODEL)

    def test_a_host_function_the_code_calls_through_the_global_object_keeps_the_global_it_writes(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'through its this under a computed key': (
                "function stage() { result = 0; new Function('n', 'this[n](1)')('hostRun'); return result; }"
                " console.log(stage());"
            ),
            'through a global object a body answers': (
                "function stage() { result = 0; new Function('n', 'Function(\"return this\")()[n](1)')('hostRun');"
                " return result; } console.log(stage());"
            ),
            'through a nested this': (
                "function stage() { result = 0; new Function('n', '(function () { return this; })()[n](1)')('hostRun');"
                " return result; } console.log(stage());"
            ),
        }, models=_THE_SUSPECTING_MODEL, host=_A_HOST_FUNCTION_WRITING_RESULT)

    @backlog
    def test_a_global_object_a_body_answers_to_any_call_is_read_through(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'called through call': (
                "globalThis.x = 5; var g = Function('return this').call(); console.log(g.x);"
            ),
            'a stored body called as a method through call': (
                "globalThis.x = 5; var f = new Function('return this'); var o = { f: f }; console.log(o.f.call(undefined).x);"
            ),
            'bound to no receiver': (
                "globalThis.x = 5; var g = Function('return this').bind()(); console.log(g.x);"
            ),
            'applied to no receiver': (
                "globalThis.x = 5; var g = Function('return this').apply(); console.log(g.x);"
            ),
            'called through Reflect.apply': (
                "globalThis.x = 5; var g = Reflect.apply(Function('return this'), undefined, []); console.log(g.x);"
            ),
            'called as a callback': (
                "globalThis.x = 5; var g = [0].map(Function('return this'))[0]; console.log(g.x);"
            ),
        })

    @backlog
    def test_code_this_analysis_cannot_read_keeps_every_name(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'the constructor of a function': (
                "var k = 5; var t = 'return a + ' + process.argv.length * 0 + ' + k';"
                " console.log((function () {}).constructor('a', t)(1));"
            ),
            'the constructor of a constructor replacing join': (
                "var code = process.argv.slice(99) + 'Array.prototype.join = function () { return \"J\"; };';"
                " [].constructor.constructor(code)(); console.log(-[5]);"
            ),
            'a function running its parameter': (
                "function live(s) { return Function(s)(); } var k = 5; console.log(live(process.argv.slice(99) + 'return k'));"
            ),
            'a text the global object handed to a call replaces': (
                "var code = 'k = 1'; function f() { Object.assign(this, { code:"
                " 'String.prototype.toUpperCase = function () { return \"patched\"; };' }); }"
                " function h(g) { f.call(g); } h(this); eval(code); console.log('ab'.toUpperCase());"
            ),
        }, models=_THE_SUSPECTING_MODEL)


class TestCodeInAStringInsideAFunctionNothingCallsKeepsNothing(_NodeDecides):

    @backlog
    def test_the_suspecting_model_removes_the_function_and_what_only_it_reaches(self):
        self.assertEachModelPrints({
            'function dead(src) { return Function(src); } var k = 5; console.log(k);': (
                'console.log(5);'
            ),
            'function d1(s) { return Function(s); } function d2(s) { return d1(s); } var k = 5; console.log(k);': (
                'console.log(5);'
            ),
            "function dead() { return eval(process.argv.slice(99) + 'k'); } var k = 5; console.log(k);": (
                'console.log(5);'
            ),
            'function dead(s) { return Function(s); } function used() { return 3; } var k = 5; console.log(k, used());': (
                'console.log(5, 3);'
            ),
            '{ function dead(src) { return Function(src); } } var k = 5; console.log(k);': (
                'console.log(5);'
            ),
            'function outer() { function dead(s) { return Function(s); } var k = 5; return k; } console.log(outer());': (
                'console.log(5);'
            ),
            (
                "function dead() { return eval(process.argv.slice(99) + 'used()'); } function used() { return 3; }"
                ' var k = 5; console.log(k, used());'
            ): (
                'console.log(5, 3);'
            ),
        }, models=_THE_SUSPECTING_MODEL)

    @backlog
    def test_the_suspecting_model_removes_a_helper_whose_calls_it_unpacks(self):
        self.assertEachModelPrints({
            "function mk(src) { return Function(src); } var k = 5; console.log(mk('return k')());": (
                'console.log(5);'
            ),
            "{ function mk(src) { return Function(src); } } var k = 5; console.log(mk('return k')());": (
                'console.log(5);'
            ),
            "var k = 1; function later(s) { return setTimeout(s, 0); } later('console.log(k)');": (
                'setTimeout(function() {\n  console.log(1);\n}, 0);'
            ),
        }, models=_THE_SUSPECTING_MODEL)

    @backlog
    def test_a_function_code_in_a_string_calls_keeps_what_it_calls(self):
        self.assertEachModelPrints({
            "function H() { return 1; } function K() { return H(); } console.log(Function('return K()')());": (
                'console.log(1);'
            ),
            (
                "function H() { return 1; } function K() { return H(); } var f = new Function('return K()');"
                ' console.log(f.call(null));'
            ): (
                "function K() {\n  return 1;\n}\nvar f = new Function('return K()');\nconsole.log(f.call(null));"
            ),
        }, models=_THE_SUSPECTING_MODEL)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAPassRemovingACallFrameKeepsWhatCallerReads(_NodeDecides):

    @backlog
    def test_a_caller_the_file_reads(self):
        caller = _A_FUNCTION_READING_ITS_CALLER
        self.assertEachModelBehavesAsTheProgramDoes({
            'a function called once': F'{caller} function main() {{ console.log(inner()); }} main();',
            'a function called in place': F'{caller} (function () {{ console.log(inner()); }})();',
            'a one-line wrapper': F'{caller} function w() {{ return inner(); }} console.log(w());',
            'a function called in place with an argument': F'{caller} console.log((function (a) {{ return inner(a); }})(1));',
            'a table function': F'{caller} var o = {{ f: function (a) {{ return inner(a); }} }}; console.log(o.f(1));',
            'a one-line wrapper with a parameter': (
                "function inner() { return inner.caller === w ? 'w' : 'other'; } function w(x) { return inner(x); }"
                ' console.log(w(1));'
            ),
            'a function called in place handing its callee on': (
                F'{caller} console.log((function (f, a) {{ return f(a); }})(inner, 1));'
            ),
            'a table function handing its callee on': (
                F'{caller} var o = {{ f: function (g, a) {{ return g(a); }} }}; console.log(o.f(inner, 1));'
            ),
            'a one-line wrapper handing its callee on': (
                F'{caller} function w(g, a) {{ return g(a); }} console.log(w(inner, 1));'
            ),
            'a function the evaluator splices': (
                F'{caller} function w(a) {{ var b = a + 1; return inner(b); }} console.log(w(1));'
            ),
            'an arrow called in place': F'{caller} console.log(((f) => f())(inner));',
            'a function the evaluator splices around an effect': (
                "function inner() { console.log(inner.caller === null ? 'top' : 'fn'); return 0; }"
                ' function w(a) { var b = a + 1; return inner(b); } w(1);'
            ),
            'an entry of a dispatcher': a_dispatcher(
                dict_lines=['"k": function () { return who(); }'],
                tail_lines=['console.log(d("k"));'],
                prefix_lines=["function who() { return who.caller.caller === null ? 'top' : 'fn'; }"],
            ),
        })

    @backlog
    def test_a_caller_code_in_a_string_reads(self):
        caller = _A_FUNCTION_READING_ITS_CALLER_IN_A_BODY
        self.assertEachModelBehavesAsTheProgramDoes({
            'a function called once': F'{caller} function main() {{ console.log(inner()); }} main();',
            'a function called in place': F'{caller} (function () {{ console.log(inner()); }})();',
            'a one-line wrapper': F'{caller} function w() {{ return inner(); }} console.log(w());',
            'a function called in place with an argument': F'{caller} console.log((function (a) {{ return inner(a); }})(1));',
            'a table function': F'{caller} var o = {{ f: function (a) {{ return inner(a); }} }}; console.log(o.f(1));',
            'a one-line wrapper with a parameter': (
                "function inner() { return Function('return inner.caller === w ? \"w\" : \"other\"')(); }"
                ' function w(x) { return inner(x); } console.log(w(1));'
            ),
            'a wrapper calling a function whose body reads the caller of its caller': (
                "function target(x) { return Function('return target.caller && target.caller.name')(); }"
                ' function viaWrapper(x) { return target(x); } console.log(viaWrapper(1));'
            ),
            'a stored body calling its caller': (
                "function A(x) { if (x === 1) return h(); return x; } var h = new Function('return h.caller(5)');"
                ' console.log(A(1));'
            ),
        })


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestACallCodeInAStringMayMakeIsNotTakenForNone(_NodeDecides):

    @backlog
    def test_a_call_of_a_function_through_call_the_code_replaces(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'the call of every function': (
                "function f(a, d) { if (!d) { d = function (x) { return 'local ' + x; }; } return d(a); }"
                " var h = new Function('Object.getPrototypeOf(function () {}).call = function (t, x) {"
                " return this.apply(t, [x, function (y) { return \"hijacked \" + y; }]); }; return arguments.length;');"
                " h(); console.log(f.call(null, 1));"
            ),
            'the call of a function the file hands the global object to': (
                "var secret = 'S'; function h() {} function f(g) { h.call(g); }"
                " var p = new Function('h.call = function (t) { console.log(t.secret); }; return arguments.length;');"
                " p(); f(this);"
            ),
        })

    @backlog
    def test_a_construction_through_the_constructor_of_an_instance(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'in eval code': (
                "function C(a, d) { if (!d) { d = function (x) { return 'local ' + x; }; } this.v = d(a); }"
                " var o = new C(1); console.log(o.v); eval(process.argv.length > 99 ? '' :"
                " 'var K = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(o), \"constructor\").value;"
                " var p = new K(2, function (y) { return \"passed \" + y; }); console.log(p.v);');"
            ),
        })


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAStringTimerKeepsWhatCallerReads(_NodeDecides):

    @backlog
    def test_a_function_a_string_timer_calls_finds_no_caller(self):
        self.assertEachModelBehavesAsTheProgramDoes({
            'a caller the file reads': F"{_A_FUNCTION_READING_ITS_CALLER} setTimeout('console.log(inner())', 0);",
            'a caller code in a string reads': (
                F"{_A_FUNCTION_READING_ITS_CALLER_IN_A_BODY} setTimeout('console.log(inner())', 0);"
            ),
        })


def _assert_the_deobfuscation_takes_time_that_grows_with_the_program(test: TestBase, small: str, large: str):
    for strict in _EITHER_MODEL:
        with test.subTest(_model(strict)):
            large_time = _fastest_deobfuscation(large, strict)
            small_time = _fastest_deobfuscation(small, strict)
            test.assertLess(processor_time_ratio(large_time, small_time), 3 * len(large) / len(small))


def _deobfuscate(source: str, strict: bool):
    deobfuscate(JsParser(source).parse(), trust_eval=not strict)


def _fastest_deobfuscation(source: str, strict: bool) -> float:
    return fastest_processor_time(functools.partial(_deobfuscate, source, strict) for _ in range(3))
