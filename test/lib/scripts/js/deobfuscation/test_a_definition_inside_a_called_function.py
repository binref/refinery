"""
A function expression the program calls where it writes it has run the definitions it holds by the
time the call returns, on every run that returns rather than throws, so the call orders them for
the code after it: a table or an accessor such a function sets up is in place for every function
the program calls later. A definition the call may skip, a read the call itself makes before the
definition, and a function that returns before its body has run are ordered by nothing.
"""
from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import node_executable
from test.lib.scripts.js.ledger import (
    NL,
    FileProgram,
    Reading,
    a_program,
    each_reading_still_prints,
    node_prints_what_each_row_pins,
    prints,
)

from refinery.lib.scripts.js.analysis.environment import HostEnvironment


#: Programs that define a name inside a function called where it is written and read it inside and
#: after the call, each with what Node makes of it as a CommonJS file and as an ES module.
A_DEFINITION_INSIDE_A_FUNCTION_CALLED_WHERE_IT_IS_WRITTEN = {
    'an accessor installed by a function called where it is written': FileProgram(
        a_program("""
            var X; (function () { var a = ["p", "q"]; X = function (i) { return a[i]; }; })(); console.log(X(0), X(1));
            """),
        prints('p q'),
        prints('p q'),
        HostEnvironment.node,
    ),
    'a throw before the definition, caught outside': FileProgram(
        a_program("""
            var X; try { (function () { throw 1; X = function () { return 1; }; })(); } catch (e) { console.log(typeof X); } console.log(typeof X);
            """),
        prints('undefined', 'undefined'),
        prints('undefined', 'undefined'),
        HostEnvironment.node,
    ),
    'a return before the definition': FileProgram(
        a_program("""
            var X; (function (c) { if (c) { return; } X = function () { return 1; }; })(process.argv.length > 0); console.log(typeof X);
            """),
        prints('undefined'),
        prints('undefined'),
        HostEnvironment.node,
    ),
    'an async function': FileProgram(
        a_program("""
            var X; (async function () { await 0; X = function () { return 1; }; })(); console.log(typeof X);
            """),
        prints('undefined'),
        prints('undefined'),
        HostEnvironment.node,
    ),
    'a generator function': FileProgram(
        a_program("""
            var X; (function* () { X = function () { return 1; }; })(); console.log(typeof X);
            """),
        prints('undefined'),
        prints('undefined'),
        HostEnvironment.node,
    ),
    'a call on one branch': FileProgram(
        a_program("""
            var X; process.argv.length > 99 && (function () { X = function () { return 1; }; })(); console.log(typeof X);
            """),
        prints('undefined'),
        prints('undefined'),
        HostEnvironment.node,
    ),
    'a read before the call': FileProgram(
        a_program("""
            var X; function g() { return typeof X; } console.log(g()); (function () { X = function () { return 4; }; })(); console.log(g(), X());
            """),
        prints('undefined', 'function 4'),
        prints('undefined', 'function 4'),
        HostEnvironment.node,
    ),
    'an arrow function': FileProgram(
        a_program("""
            var X; (() => { X = () => 7; })(); console.log(X());
            """),
        prints('7'),
        prints('7'),
        HostEnvironment.node,
    ),
    'a call in a loop, the definition on its second run': FileProgram(
        a_program("""
            var X; for (var k = 0; k < 2; k++) { (function () { if (k === 1) { X = function () { return k; }; } })(); } console.log(typeof X);
            """),
        prints('function'),
        prints('function'),
        HostEnvironment.node,
    ),
    'a definition after a try that may throw inside': FileProgram(
        a_program("""
            var X; (function () { try { JSON.parse("{"); } catch (e) {} X = function () { return 3; }; })(); console.log(X());
            """),
        prints('3'),
        prints('3'),
        HostEnvironment.node,
    ),
    'a definition inside a finally': FileProgram(
        a_program("""
            var X; try { (function () { try { throw 1; } finally { X = function () { return 5; }; } })(); } catch (e) {} console.log(typeof X);
            """),
        prints('function'),
        prints('function'),
        HostEnvironment.node,
    ),
    'nested immediate calls': FileProgram(
        a_program("""
            var X; (function () { (function () { X = function () { return 8; }; })(); })(); console.log(X());
            """),
        prints('8'),
        prints('8'),
        HostEnvironment.node,
    ),
    'the call inside a function called later': FileProgram(
        a_program("""
            var X; function setup() { (function () { X = function () { return 9; }; })(); } function use() { return typeof X; } console.log(use()); setup(); console.log(use());
            """),
        prints('undefined', 'function'),
        prints('undefined', 'function'),
        HostEnvironment.node,
    ),
    'a read in a function the immediate call runs before the definition': FileProgram(
        a_program("""
            var X; (function () { var a = ["p"]; function g() { return X(0); } try { console.log(g()); } catch (e) { console.log("early"); } X = function (i) { return a[i]; }; })(); console.log(X(0));
            """),
        prints('early', 'p'),
        prints('early', 'p'),
        HostEnvironment.node,
    ),
    'a top-level function the immediate call runs before its definition': FileProgram(
        a_program("""
            var X; function use() { return typeof X; } (function () { console.log(use()); X = function () { return 1; }; })(); console.log(use());
            """),
        prints('undefined', 'function'),
        prints('undefined', 'function'),
        HostEnvironment.node,
    ),
    'same with a call of X': FileProgram(
        a_program("""
            var X; function use() { try { return X(); } catch (e) { return "early"; } } (function () { console.log(use()); X = function () { return 1; }; })(); console.log(use());
            """),
        prints('early', '1'),
        prints('early', '1'),
        HostEnvironment.node,
    ),
    'a read in the same statement before the call': FileProgram(
        a_program("""
            var X; console.log(typeof X, (function () { X = function () { return 1; }; })());
            """),
        prints('undefined undefined'),
        prints('undefined undefined'),
        HostEnvironment.node,
    ),
    'a call of X in the same statement before the call': FileProgram(
        a_program("""
            var X; try { console.log(X(), (function () { X = function () { return 1; }; })()); } catch (e) { console.log("early"); } console.log(X());
            """),
        (F'early{NL}', 'TypeError'),
        (F'early{NL}', 'TypeError'),
        HostEnvironment.node,
    ),
    'a read in the call arguments': FileProgram(
        a_program("""
            var X; (function (v) { X = function () { return 1; }; console.log(v); })(typeof X);
            """),
        prints('undefined'),
        prints('undefined'),
        HostEnvironment.node,
    ),
    'a definition in a loop that may not run': FileProgram(
        a_program("""
            var X; (function () { for (var i = 0; i < process.argv.length - 99; i++) { X = function () { return 1; }; } })(); console.log(typeof X);
            """),
        prints('undefined'),
        prints('undefined'),
        HostEnvironment.node,
    ),
    'a throw caught inside before the definition': FileProgram(
        a_program("""
            var X; (function () { try { if (process.argv.length > 0) { throw 1; } X = function () { return 1; }; } catch (e) {} })(); console.log(typeof X);
            """),
        prints('undefined'),
        prints('undefined'),
        HostEnvironment.node,
    ),
    'a labeled break past the definition': FileProgram(
        a_program("""
            var X; (function () { b: { if (process.argv.length > 0) { break b; } X = function () { return 1; }; } })(); console.log(typeof X);
            """),
        prints('undefined'),
        prints('undefined'),
        HostEnvironment.node,
    ),
    'a return in finally over a throw': FileProgram(
        a_program("""
            var X; (function () { var c = process.argv.length > 0; try { if (c) { throw 1; } } finally { if (c) { return; } } X = function () { return 1; }; })(); console.log(typeof X);
            """),
        prints('undefined'),
        prints('undefined'),
        HostEnvironment.node,
    ),
    'the accessor read in a getter triggered inside the call': FileProgram(
        a_program("""
            var X; var o = { get v() { return typeof X; } }; (function () { console.log(o.v); X = function () { return 1; }; })(); console.log(o.v);
            """),
        prints('undefined', 'function'),
        prints('undefined', 'function'),
        HostEnvironment.node,
    ),
    'recursion re-enters the function': FileProgram(
        a_program("""
            var X; (function f(n) { if (n) { console.log(typeof X); return; } f(1); X = function () { return 1; }; })(0); console.log(typeof X);
            """),
        prints('undefined', 'function'),
        prints('undefined', 'function'),
        HostEnvironment.node,
    ),
    'an async arrow': FileProgram(
        a_program("""
            var X; (async () => { await 0; X = function () { return 1; }; })(); console.log(typeof X);
            """),
        prints('undefined'),
        prints('undefined'),
        HostEnvironment.node,
    ),
    'a callback run inside the call before the definition': FileProgram(
        a_program("""
            var X; (function () { [1].forEach(function () { console.log(typeof X); }); X = function () { return 1; }; })(); console.log(typeof X);
            """),
        prints('undefined', 'function'),
        prints('undefined', 'function'),
        HostEnvironment.node,
    ),
    'the accessor shape, read inside the call before it is set': FileProgram(
        a_program("""
            var SC; (function () { var s = "a|b".split("|"); function peek() { try { return SC(1); } catch (e) { return "early"; } } console.log(peek()); SC = function (i) { return s[i]; }; })(); console.log(SC(0));
            """),
        prints('early', 'a'),
        prints('early', 'a'),
        HostEnvironment.node,
    ),
    'a value set in a called function, read by a function called later': FileProgram(
        a_program("""
            var T; (function () { T = ["a", "b"]; })(); function f(i) { return T[i]; } console.log(f(0), f(1));
            """),
        prints('a b'),
        prints('a b'),
        HostEnvironment.node,
    ),
    'the value set only on one path of the called function': FileProgram(
        a_program("""
            var T; (function (c) { if (c) { T = ["a"]; } })(process.argv.length > 99); function f() { return T && T[0]; } console.log(f());
            """),
        prints('undefined'),
        prints('undefined'),
        HostEnvironment.node,
    ),
    'a function created after the call reads the value': FileProgram(
        a_program("""
            var T; (function () { T = { k: 1 }; })(); var g = function () { return T.k; }; console.log(g());
            """),
        prints('1'),
        prints('1'),
        HostEnvironment.node,
    ),
    'the function read inside the called function before the value is set': FileProgram(
        a_program("""
            var T; function f() { return typeof T; } (function () { console.log(f()); T = 1; })(); console.log(f());
            """),
        prints('undefined', 'number'),
        prints('undefined', 'number'),
        HostEnvironment.node,
    ),
    'the called function re-run through its own name': FileProgram(
        a_program("""
            var T, n = 0; (function g() { if (n++ === 0) { g(); } T = n; })(); function f() { return T; } console.log(f());
            """),
        prints('2'),
        prints('2'),
        HostEnvironment.node,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestADefinitionInsideAFunctionCalledWhereItIsWrittenStillPrintsWhatItPrints(TestBase):

    def testnode_prints_what_each_row_pins(self):
        node_prints_what_each_row_pins(self, A_DEFINITION_INSIDE_A_FUNCTION_CALLED_WHERE_IT_IS_WRITTEN)

    def test_each_program_still_prints_what_it_prints(self):
        each_reading_still_prints(
            self,
            A_DEFINITION_INSIDE_A_FUNCTION_CALLED_WHERE_IT_IS_WRITTEN,
            (Reading.COMMONJS,),
        )
