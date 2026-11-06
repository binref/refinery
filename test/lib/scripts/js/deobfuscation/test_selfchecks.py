"""
Every program here is written by hand, because Node runs each of them.

Each hash constant is what the program's own helper computes in Node for the guarded function; a
wrong constant makes the program print `tampered`, which fails the tests that compare what it
prints.
"""
from __future__ import annotations

import inspect
import textwrap
import unittest

from test import TestBase, opportunity
from test.lib.scripts.js.analysis.differential import (
    behavior,
    completion_values,
    deobfuscate_source,
    node_executable,
)
from test.lib.scripts.js.ledger import before_and_after, each_program_still_prints

from refinery.lib.scripts.js.analysis.cache import ModelCache
from refinery.lib.scripts.js.analysis.conversions import ConversionSettlement
from refinery.lib.scripts.js.deobfuscation.selfchecks import JsSelfCheckFolding
from refinery.lib.scripts.js.options import ExecutionModel
from refinery.lib.scripts.js.parser import JsParser

#: One line long, so the check finds no line break in the function that holds it.
LINE_BREAK_CHECK = (
    r'var n = function () { const t = function () { const r = new RegExp("\n"); return r["test"](n); }; '
    r'if (t()) { console.log("tampered"); } }; return n();'
)

LINE_BREAK_MARKER = 'new RegExp('

INSERTED_LINE_BREAK_CHECK = (
    r'function () { var n = function () { const t = function () { const r = new RegExp("\n"); return r.test(n); }; '
    'return t(); }; return n(); }()'
)

INSERTED_LINE_BREAK_LOCK = F'if ({INSERTED_LINE_BREAK_CHECK}) {{ console.log("tampered"); }}'

NEW_HELPERS = inspect.cleandoc(r'''
    function MathImulPolyfill(opA, opB) {
        opB |= 0;
        var result = (opA & 0x003fffff) * opB;
        if (opA & 0xffc00000) result += (opA & 0xffc00000) * opB | 0;
        return result | 0;
    }
    var imul = Math["imul"] || MathImulPolyfill;
    function hashText(str, seed) {
        var h1 = 0xdeadbeef ^ seed;
        var h2 = 0x41c6ce57 ^ seed;
        for (var i = 0, ch; i < str.length; i++) {
            ch = str.charCodeAt(i);
            h1 = imul(h1 ^ ch, 2654435761);
            h2 = imul(h2 ^ ch, 1597334677);
        }
        h1 = imul(h1 ^ (h1 >>> 16), 2246822507) ^ imul(h2 ^ (h2 >>> 13), 3266489909);
        h2 = imul(h2 ^ (h2 >>> 16), 2246822507) ^ imul(h1 ^ (h1 >>> 13), 3266489909);
        return 4294967296 * (2097151 & h2) + (h1 >>> 0);
    }
    function hashOf(fnObject, seed, regex = new RegExp(" |\\n|;|,|\\{|\\}|\\(|\\)|\\.|\\[|\\]", "g")) {
        var fnStringed = fnObject["toString"]()["replace"](regex, "");
        return hashText(fnStringed, seed);
    }
''')

LOOK_ALIKE_HELPERS = NEW_HELPERS.replace('h1 >>> 16), 2246822507) ^', 'h1 >>> 15), 2246822507) ^')

OLD_HELPERS = inspect.cleandoc(r'''
    var imul = Math.imul || function (opA, opB) {
        opB |= 0;
        var result = (opA & 4194303) * opB;
        if (opA & 4290772992) result += (opA & 4290772992) * opB | 0;
        return result | 0;
    };
    function hashText(str, seed) {
        var h1 = 0xdeadbeef ^ seed;
        var h2 = 0x41c6ce57 ^ seed;
        for (var i = 0, ch; i < str.length; i++) {
            ch = str.charCodeAt(i);
            h1 = imul(h1 ^ ch, 2654435761);
            h2 = imul(h2 ^ ch, 1597334677);
        }
        h1 = imul(h1 ^ (h1 >>> 16), 2246822507) ^ imul(h2 ^ (h2 >>> 13), 3266489909);
        h2 = imul(h2 ^ (h2 >>> 16), 2246822507) ^ imul(h1 ^ (h1 >>> 13), 3266489909);
        return 4294967296 * (2097151 & h2) + (h1 >>> 0);
    }
    function textOf(x) { return x.toString().replace(/ |\n|;|,|\{|\}|\(|\)|\.|\[|\]/g, ""); }
''')

_HASH_RETURN = '    return 4294967296 * (2097151 & h2) + (h1 >>> 0);'


def joined(*lines: str) -> str:
    return ''.join(F'{line}\n' for line in lines if line)


def run_once(*lines: str) -> str:
    body = textwrap.indent('\n'.join(lines), '    ')
    return F'(function () {{\n{body}\n}})();'


def inserted_at_the_start_of_the_hash(statement: str, helpers: str = OLD_HELPERS) -> str:
    start = 'function hashText(str, seed) {\n'
    return helpers.replace(start, F'{start}{textwrap.indent(statement, " " * 4)}\n')


def inserted_at_the_start_of_the_hash_loop(statement: str, helpers: str = OLD_HELPERS) -> str:
    start = 'i < str.length; i++) {\n'
    return helpers.replace(start, F'{start}{textwrap.indent(statement, " " * 8)}\n')


def inserted_before_the_hash_returns(statement: str) -> str:
    return OLD_HELPERS.replace(_HASH_RETURN, F'{textwrap.indent(statement, " " * 4)}\n{_HASH_RETURN}')


CONTEXT_HELPERS = inserted_before_the_hash_returns('if (!ctx["missingContext"]) { tripped = "yes"; }')

CRASH_HELPERS = inserted_before_the_hash_returns(inspect.cleandoc('''
    if (!ctx["process"]) {
        var crashVar = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        while (true) { crashVar = crashVar; if (!crashVar) break; }
    }
'''))

DATED_HELPERS = inserted_at_the_start_of_the_hash('if (Date.now() > 4000000000000) { console.log("late"); }')

LOOP_DATED_HELPERS = inserted_at_the_start_of_the_hash_loop('if (Date.now() > 4000000000000) { console.log("late"); }')

DOUBLE = 'function double(x) { return x * 2; }'
SMILE = 'function smile(x) { return x + "' + chr(0x1F600) + '"; }'
GREET = 'function greet(x) { return `hi ${x}`; }'
NAME_OF = 'function nameOf(x) { return x["name"]; }'
PROGRAM = 'function program() { console.log("ran"); }'
PROGRAM_READING_A_KEY = 'function program() { console.log({ name: "ran" }["name"]); }'
PROGRAM_READING_TRIPPED = 'function program() { console.log("ran", typeof tripped); }'

DOUBLE_42 = 8332086338560561
SMILE_7 = 6376619314661907
GREET_3 = 4670964258068317
NAME_OF_5 = 6806156106331032
LOOK_ALIKE_DOUBLE_42 = 1155131416700091
PROGRAM_25 = 4345407897497152
PROGRAM_READING_A_KEY_25 = 4939227658243236
PROGRAM_READING_TRIPPED_25 = 7786884700990675


def guarded(
    subject: str,
    name: str,
    seed: int,
    constant: int,
    tail: str,
    helpers: str = NEW_HELPERS,
    before: str = '',
) -> str:
    guard = inspect.cleandoc(F'''
        function guarded() {{
            var h = guarded.memo || (guarded.memo = hashOf({name}, {seed}));
            if (h === {constant}) {{ return {name}(...arguments); }} else {{ console.log("tampered"); }}
        }}
    ''')
    return joined(before, helpers, subject, guard, tail)


def after_the_new_helpers(program: str) -> str:
    return joined(NEW_HELPERS, program)


def wrapped(constant: int, helpers: str = OLD_HELPERS, program: str = PROGRAM, before: str = '') -> str:
    return joined(before, run_once(
        helpers,
        program,
        'var h = hashText(textOf(program), 25);',
        F'if (h == {constant}) {{ return program.apply(this, arguments); }} else {{ console.log("tampered"); }}',
    ))


def checked(statement: str = LINE_BREAK_CHECK, tail: str = 'console.log("ran");', before: str = '') -> str:
    return joined(before, F'(function () {{ {statement} }})();', tail)


A_HASH_WHOSE_MATCH_STATICS_ARE_SET_AGAIN_BEFORE_A_READ = (
    wrapped(PROGRAM_25, inserted_at_the_start_of_the_hash(INSERTED_LINE_BREAK_LOCK))
    + r'if (/(\d+)/.test("abc 123")) { console.log("$1=" + RegExp.$1); }'
)

A_CHECK_THE_INPUT_TEXT_DECIDES = {
    checked(): ('ran\n', LINE_BREAK_MARKER),
    inspect.cleandoc(F'''
        {INSERTED_LINE_BREAK_LOCK}
        console.log("ran");
    '''): ('ran\n', LINE_BREAK_MARKER),
    inspect.cleandoc(F'''
        function f(k) {{
            for (let i = 0; i < k; i++) {{
                (function () {{ {LINE_BREAK_CHECK} }})();
            }}
            return k;
        }}
        console.log(f(3));
    '''): ('3\n', LINE_BREAK_MARKER),
    checked(
        r'var x = function () { const y = function () { const y = new RegExp("\n"); return y.test(x); }; '
        'if (y()) { console.log("tampered"); } }; return x();'
    ): ('ran\n', LINE_BREAK_MARKER),
    inspect.cleandoc(F'''
        if (/(\\d+)/.test("abc 123")) {{
            (function () {{ {LINE_BREAK_CHECK} }})();
            console.log("$1=" + RegExp.$1);
        }}
    '''): ('$1=123\n', LINE_BREAK_MARKER),
    guarded(DOUBLE, 'double', 42, DOUBLE_42, 'console.log(guarded(21), guarded(4));'): (
        '42 8\n', str(DOUBLE_42)),
    guarded(SMILE, 'smile', 7, SMILE_7, 'console.log(guarded("a"));'): (
        'a' + chr(0x1F600) + '\n', str(SMILE_7)),
    guarded(GREET, 'greet', 3, GREET_3, 'console.log(guarded("you"));'): (
        'hi you\n', str(GREET_3)),
    guarded(NAME_OF, 'nameOf', 5, NAME_OF_5, 'console.log(guarded({ name: "you" }));'): (
        'you\n', str(NAME_OF_5)),
    wrapped(PROGRAM_25): ('ran\n', str(PROGRAM_25)),
    after_the_new_helpers(inspect.cleandoc('''
        function double(x) { return x * 2; }
        function guarded() { guarded.memo || (guarded.memo = hashOf(double, 42)); return double(...arguments); }
        console.log(guarded(21));
    ''')): ('42\n', 'hashOf('),
    wrapped(PROGRAM_25, inserted_at_the_start_of_the_hash(INSERTED_LINE_BREAK_LOCK)): ('ran\n', str(PROGRAM_25)),
    A_HASH_WHOSE_MATCH_STATICS_ARE_SET_AGAIN_BEFORE_A_READ: ('ran\n$1=123\n', str(PROGRAM_25)),
    inspect.cleandoc(r'''
        var N = function () { return 1; };
        var saved = [N];
        var T = function () { const R = new RegExp("\n"); return R.test(N); };
        if (T()) { console.log("tampered"); } else { console.log("clean"); }
        console.log(saved.length);
    '''): ('clean\n1\n', LINE_BREAK_MARKER),
    guarded(DOUBLE, 'double', 42, DOUBLE_42, inspect.cleandoc('''
        var keep = [double];
        console.log(guarded(21), guarded(4), keep.length);
    ''')): ('42 8 1\n', str(DOUBLE_42)),
    guarded(DOUBLE, 'double', 42, DOUBLE_42, inspect.cleandoc('''
        function use(f) { return [f]; }
        console.log(guarded(21), use(double).length);
    ''')): ('42 1\n', str(DOUBLE_42)),
    (
        r'(function (...m) { m.length = 0; m[9] = function () { const t = function () { const r = new RegExp("\n"); '
        r'return r.test(m[9]); }; if (t()) { console.log("tampered"); } }; return m[9](); })(); console.log("ran");'
    ): ('ran\n', LINE_BREAK_MARKER),
}

#: The hash replaces text with a regular expression, which resets the match statics of `RegExp`:
#: after the hash runs, `RegExp.$1` is empty.
A_CHECK_DECIDED_WHERE_THE_HASH_IS_OBSERVED = {
    guarded(
        DOUBLE, 'double', 42, DOUBLE_42,
        r'if (/(\d+)/.test("abc 123")) { guarded(1); console.log("$1=" + globalThis.RegExp.$1); }',
    ): ('$1=\n', 'hashOf(double, 42)', str(DOUBLE_42)),
    guarded(
        DOUBLE, 'double', 42, DOUBLE_42,
        r'if (/(\d+)/.test("abc 123")) { guarded(1); console.log("$1=" + new RegExp("a").constructor.$1); }',
    ): ('$1=\n', 'hashOf(double, 42)', str(DOUBLE_42)),
}

A_CHECK_DECIDED_WHERE_THE_HASH_IS_OBSERVED_IN_ANOTHER_SPELLING = {
    guarded(
        DOUBLE, 'double', 42, DOUBLE_42,
        r'if (/(\d+)/.test("abc 123")) { guarded(1); var R = /x/.constructor; console.log("$1=" + R.$1); }',
    ): ('$1=\n', 'hashOf(double, 42)', str(DOUBLE_42)),
    after_the_new_helpers(inspect.cleandoc(r'''
        function double(x) { return x * 2; }
        function guarded() {
            for (var h = guarded.memo || (guarded.memo = hashOf(double, 42)); ; ) {
                if (h === 8332086338560561) { return double(...arguments); } else { console.log("tampered"); }
                break;
            }
        }
        if (/(\d+)/.test("abc 123")) { console.log(guarded(21)); console.log("$1=" + RegExp.$1); }
    ''')): ('42\n$1=\n', 'hashOf(double, 42)', str(DOUBLE_42)),
}

A_CHECK_DECIDED_OVER_A_HELPER_CALLING_WHAT_THE_HOST_PASSED = {
    wrapped(
        PROGRAM_25,
        inserted_at_the_start_of_the_hash('if (require("os").platform() === "x") { console.log("os"); }'),
    ): ('ran\n', str(PROGRAM_25)),
}

A_CHECK_DECIDED_OVER_HELPERS_CARRYING_AN_INSERTED_CHECK = {
    wrapped(PROGRAM_READING_TRIPPED_25, CONTEXT_HELPERS, PROGRAM_READING_TRIPPED, before='var ctx = globalThis;'): (
        'ran string\n', str(PROGRAM_READING_TRIPPED_25)),
    wrapped(PROGRAM_25, CRASH_HELPERS, before='var ctx = globalThis;'): ('ran\n', str(PROGRAM_25)),
    wrapped(PROGRAM_READING_A_KEY_25, DATED_HELPERS, PROGRAM_READING_A_KEY): (
        'ran\n', str(PROGRAM_READING_A_KEY_25)),
    wrapped(
        PROGRAM_25,
        OLD_HELPERS.replace(
            'function textOf(x) { ',
            'function textOf(x) { if (Date.now() < 4000000000000) { console.log("dated"); } ',
        ),
    ): ('dated\nran\n', str(PROGRAM_25)),
    wrapped(PROGRAM_25, LOOP_DATED_HELPERS): ('ran\n', str(PROGRAM_25)),
}

SET_A_LINE_BREAK = r'function () { return "a\nb"; }'


def checked_by_name(route: str, prefix: str = '') -> str:
    return (
        '(function () { var N = function () { '
        + prefix
        + r'const T = function () { const R = new RegExp("\n"); return R["test"](N); }; '
        'if (T()) { console.log("tampered"); } else { console.log("fine"); } }; '
        + route
        + 'return N(); })();\n'
    )


#: The clock reads 4000000000000 on 2096-10-02, a day inside the window the clock may read. Each
#: program maps to what it prints today and to what it prints or throws in 2098.
A_CHECK_THE_CLOCK_DECIDES = {
    wrapped(PROGRAM_25, inserted_at_the_start_of_the_hash('if (Date.now() > 4000000000000) { seed = 1; }')): (
        'ran\n', ('tampered\n', None)
    ),
    wrapped(PROGRAM_25, inserted_at_the_start_of_the_hash('if (Date.now() > 4000000000000) { return 1; }')): (
        'ran\n', ('tampered\n', None)
    ),
    wrapped(PROGRAM_25, inserted_at_the_start_of_the_hash('if (Date.now() > 4000000000000) { imul = null; }')): (
        'ran\n', ('', 'TypeError')
    ),
    wrapped(PROGRAM_25, inserted_at_the_start_of_the_hash(
        'if (Date.now() > 4000000000000) { String.prototype.charCodeAt = function () { return 0; }; }'
    )): (
        'ran\n', ('tampered\n', None)
    ),
    wrapped(PROGRAM_25, inserted_before_the_hash_returns('if (Date.now() < 4000000000000) { with ({}) { h2 = 0; } }')): (
        'tampered\n', ('ran\n', None)
    ),
    wrapped(PROGRAM_25, inserted_before_the_hash_returns('if (Date.now() < 4000000000000) { eval("h2 = 0"); }')): (
        'tampered\n', ('ran\n', None)
    ),
    wrapped(PROGRAM_25, inserted_before_the_hash_returns('if (Date.now() < 4000000000000) { function h2() {} }')): (
        'tampered\n', ('ran\n', None)
    ),
}

IN_2098 = 'Date.now = function () { return 4050000000000; };'

A_CHECK_THE_INPUT_TEXT_DOES_NOT_DECIDE = {
    checked(inspect.cleandoc(r'''
        var n = function () {
            const t = function () { const r = new RegExp("\n"); return r.test(n); };
            if (t()) { console.log("tampered"); }
        };
        return n();
    ''')): 'tampered\nran\n',
    checked(before='RegExp.prototype.test = function () { return true; };'): 'tampered\nran\n',
    checked(before=r'Function.prototype.toString = function () { return "\n"; };'): 'tampered\nran\n',
    checked(before=r'Object.prototype[Symbol.toPrimitive] = function () { return "\n"; };'): 'tampered\nran\n',
    checked(
        r'var n = function () { const t = function () { const r = new RegExp("\n"); return r.test(n); }; '
        r'if (t()) { console.log("tampered"); } }; n.toString = function () { return "\n"; }; return n();'
    ): 'tampered\nran\n',
    checked(before='var RegExp = function () { return { test: function () { return true; } }; };'): 'tampered\nran\n',
    checked(before=inspect.cleandoc('''
        function patch(R) { R.prototype.test = function () { return true; }; }
        patch(RegExp);
    ''')): 'tampered\nran\n',
    checked(before='(function (R) { R.prototype.test = function () { return true; }; })(RegExp);'): 'tampered\nran\n',
    checked(before='Reflect.set(RegExp.prototype, "test", function () { return true; });'): 'tampered\nran\n',
    checked(before='globalThis.RegExp.prototype.test = function () { return true; };'): 'tampered\nran\n',
    checked(
        before='globalThis.Object.prototype[Symbol.toPrimitive] = function () { return "a" + String.fromCharCode(10); };',
    ): 'tampered\nran\n',
    checked(
        r'var n = function m() { m.toString = function () { return "\n"; }; '
        r'const t = function () { const r = new RegExp("\n"); return r.test(n); }; '
        'if (t()) { console.log("tampered"); } }; return n();'
    ): 'tampered\nran\n',
    checked(
        LINE_BREAK_CHECK.replace('return n();', 'n instanceof X; return n();'),
        before=r'class X { static [Symbol.hasInstance](v) { v.toString = function () { return "\n"; }; return false; } }',
    ): 'tampered\nran\n',
    inspect.cleandoc(r'''
        var N = function () {};
        var T = function () { const R = new RegExp("\n"); return R.test(N); };
        globalThis["N"] = function () {
        };
        if (T()) { console.log("tampered"); } else { console.log("clean"); }
    '''): 'clean\n',
    checked_by_name(F'var o = new N(); o.constructor.toString = {SET_A_LINE_BREAK}; ', 'if (new.target) { return; } '): (
        'tampered\n'
    ),
    checked_by_name('new N(); ', F'if (new.target) {{ new.target.toString = {SET_A_LINE_BREAK}; return; }} '): (
        'tampered\n'
    ),
    checked_by_name(
        F'var B = N.bind(null); new B().constructor.toString = {SET_A_LINE_BREAK}; ', 'if (new.target) { return; } '
    ): 'tampered\n',
    checked_by_name(F'(function (s, v) {{ v.toString = {SET_A_LINE_BREAK}; }})`${{N}}`; '): 'tampered\n',
    checked_by_name(F'function g() {{ g.caller.toString = {SET_A_LINE_BREAK}; }} ', 'g(); '): 'tampered\n',
    guarded(DOUBLE, 'double', 42, DOUBLE_42 + 1, 'console.log(guarded(21));'): 'tampered\nundefined\n',
    guarded(DOUBLE, 'double', 42, DOUBLE_42, 'console.log(guarded(21), typeof guarded.memo);'): '42 number\n',
    guarded(DOUBLE, 'double', 42, DOUBLE_42, 'console.log(guarded(21), Object.keys(guarded).length);'): '42 1\n',
    guarded(
        DOUBLE, 'double', 42, LOOK_ALIKE_DOUBLE_42, 'console.log(guarded(21));', helpers=LOOK_ALIKE_HELPERS
    ): '42\n',
    guarded(DOUBLE, 'double', 42, DOUBLE_42, 'console.log(guarded(21));', helpers=LOOK_ALIKE_HELPERS): (
        'tampered\nundefined\n'
    ),
    guarded(
        DOUBLE, 'double', 42, DOUBLE_42, 'console.log(guarded(21));',
        before='String.prototype.replace = function () { return "x"; };',
    ): 'tampered\nundefined\n',
    guarded(
        DOUBLE, 'double', 42, DOUBLE_42, 'console.log(guarded(21));',
        helpers=NEW_HELPERS.replace('|| MathImulPolyfill', '|| function (a, b) { return 0; }'),
        before='delete Math.imul;',
    ): 'tampered\nundefined\n',
    after_the_new_helpers(inspect.cleandoc('''
        function double(x) { return x * 2; }
        function guarded() {
            if (h === 8332086338560561) { return double(...arguments); } else { console.log("tampered"); }
            var h = guarded.memo || (guarded.memo = hashOf(double, 42));
        }
        console.log(guarded(21));
    ''')): 'tampered\nundefined\n',
    guarded(
        DOUBLE, 'double', 42, DOUBLE_42,
        inspect.cleandoc('''
            Object.freeze(guarded);
            try { console.log(guarded(21)); } catch (e) { console.log(e.constructor.name); }
        '''),
        before='"use strict";',
    ): 'TypeError\n',
    wrapped(PROGRAM_25 + 1): 'tampered\n',
    wrapped(PROGRAM_25, inserted_at_the_start_of_the_hash('if (new.target) { console.log("constructed"); }')): 'ran\n',
    **{source: prints_today for source, (prints_today, _) in A_CHECK_THE_CLOCK_DECIDES.items()},
    checked(LINE_BREAK_CHECK.replace('const t = function ()', 'const t = async function ()')): 'tampered\nran\n',
    checked(LINE_BREAK_CHECK.replace('const t = function ()', 'const t = async () =>')): 'tampered\nran\n',
    checked(LINE_BREAK_CHECK.replace('const t = function ()', 'const t = function* ()')): 'tampered\nran\n',
    (
        '(function () { var N; var keep = (N = function () { '
        r'const T = function () { const R = new RegExp("\n"); return R["test"](N); }; '
        'if (T()) { console.log("tampered"); } else { console.log("fine"); } }); '
        F'keep.toString = {SET_A_LINE_BREAK}; return N(); }})();'
    ): 'tampered\n',
    guarded(DOUBLE, 'double', 42, DOUBLE_42, 'console.log(guarded(21));').replace('guarded.memo', 'guarded.name'): (
        'tampered\nundefined\n'
    ),
    guarded(DOUBLE, 'double', 42, DOUBLE_42, 'console.log(guarded(21));').replace('guarded.memo', 'guarded.call'): (
        'tampered\nundefined\n'
    ),
    guarded(
        DOUBLE, 'double', 42, DOUBLE_42,
        'try { console.log(guarded(21)); } catch (e) { console.log(e.constructor.name); }',
        helpers=NEW_HELPERS.replace('var imul = Math["imul"] || MathImulPolyfill;\n', '').replace('imul(', 'IMUL('),
    ): 'ReferenceError\n',
    guarded(
        DOUBLE, 'double', 42, DOUBLE_42,
        'try { console.log(guarded(21)); } catch (e) { console.log(e.constructor.name); }',
        helpers=NEW_HELPERS.replace('return hashText(fnStringed, seed)', 'return HASH(fnStringed, seed)'),
    ): 'ReferenceError\n',
}

A_HASH_THE_MODULE_EXPORTS = {
    after_the_new_helpers(inspect.cleandoc('''
        function double(x) { return x * 2; }
        export var h = hashOf(double, 42);
        if (h === 8332086338560561) { console.log(double(21)); } else { console.log("tampered"); }
    ''')): '42\n',
}

A_HASH_COMPARED_WITH_NO_INTEGER = {
    inspect.cleandoc('''
        function f(a) { var r = Math.min(a, 1 / 0); if (r === 0) { return 1; } return 2; }
        console.log(f(process.argv.length));
    '''): '2\n',
    inspect.cleandoc('''
        function g(a, b) { return a + b; }
        function f(a) { var r = g(a, 1e999); if (r === 5) { return 1; } return 2; }
        console.log(f(3));
    '''): '2\n',
}


A_LONE_HASH_CALL_OVER_A_FUNCTION_HANDED_ON = joined(
    run_once(OLD_HELPERS, PROGRAM, 'hashText(textOf(program), 25);', 'keep(program);'),
    'function keep(f) { return [f]; }',
)

A_SCRIPT_ENDING_WHERE_A_HASH_IS_DECIDED = (
    joined(OLD_HELPERS, PROGRAM, 'hashText(textOf(program), 25);'),
    joined(
        'var ctx = globalThis;',
        CONTEXT_HELPERS,
        PROGRAM_READING_TRIPPED,
        'var h = hashText(textOf(program), 25);',
        F'function run() {{ if (h == {PROGRAM_READING_TRIPPED_25}) {{ return program(); }} else {{ console.log("tampered"); }} }}',
    ),
)


class TestTheCheckTheInputTextDecidesIsGone(TestBase):

    def test_the_deobfuscation_no_longer_holds_the_check(self):
        for source, (_, marker) in A_CHECK_THE_INPUT_TEXT_DECIDES.items():
            with self.subTest(source):
                self.assertNotIn(marker, deobfuscate_source(source, execution=ExecutionModel.module))

    def test_the_hash_call_stays_where_its_match_statics_may_be_read(self):
        for source, (_, kept, constant) in A_CHECK_DECIDED_WHERE_THE_HASH_IS_OBSERVED.items():
            with self.subTest(source):
                text = deobfuscate_source(source, execution=ExecutionModel.module)
                self.assertIn(kept, text)
                self.assertNotIn(constant, text)

    def test_the_hash_call_stays_where_its_match_statics_are_read_in_another_spelling(self):
        for source, (_, kept, _) in A_CHECK_DECIDED_WHERE_THE_HASH_IS_OBSERVED_IN_ANOTHER_SPELLING.items():
            with self.subTest(source):
                self.assertIn(kept, deobfuscate_source(source, execution=ExecutionModel.module))

    @opportunity
    def test_the_comparison_goes_where_the_hash_match_statics_are_read_in_another_spelling(self):
        for source, (_, _, constant) in A_CHECK_DECIDED_WHERE_THE_HASH_IS_OBSERVED_IN_ANOTHER_SPELLING.items():
            with self.subTest(source):
                self.assertNotIn(constant, deobfuscate_source(source, execution=ExecutionModel.module))

    def test_the_hash_call_stays_where_its_helpers_carry_an_inserted_check(self):
        for source, (_, constant) in A_CHECK_DECIDED_OVER_HELPERS_CARRYING_AN_INSERTED_CHECK.items():
            with self.subTest(source):
                text = deobfuscate_source(source, execution=ExecutionModel.module)
                self.assertIn('hashText(textOf(program), 25);', text)
                self.assertNotIn(constant, text)

    def test_a_check_over_a_helper_calling_what_the_host_passed_is_gone(self):
        for source, (_, constant) in A_CHECK_DECIDED_OVER_A_HELPER_CALLING_WHAT_THE_HOST_PASSED.items():
            for execution in (ExecutionModel.commonjs, ExecutionModel.module):
                with self.subTest(execution=execution.name):
                    self.assertNotIn(constant, deobfuscate_source(source, execution=execution))

    def test_a_hash_call_nothing_reads_goes_once_its_inserted_check_is_decided(self):
        source = wrapped(
            PROGRAM_25,
            inserted_at_the_start_of_the_hash(F'if ({INSERTED_LINE_BREAK_CHECK}) {{ console.log("tampered"); }} '),
        )
        self.assertNotIn('hashText', deobfuscate_source(source, execution=ExecutionModel.module))

    @opportunity
    def test_a_hash_call_whose_match_statics_are_set_again_before_a_read_goes(self):
        source = A_HASH_WHOSE_MATCH_STATICS_ARE_SET_AGAIN_BEFORE_A_READ
        self.assertNotIn('hashText', deobfuscate_source(source, execution=ExecutionModel.module))


class TestTheCheckTheInputTextDoesNotDecideStays(TestBase):

    def test_a_comparison_of_the_clock_inside_the_window_stays(self):
        for source in A_CHECK_THE_CLOCK_DECIDES:
            with self.subTest(source):
                self.assertIn('Date.now()', deobfuscate_source(source, execution=ExecutionModel.module))

    def test_the_deobfuscation_still_exports_the_hash(self):
        for source in A_HASH_THE_MODULE_EXPORTS:
            with self.subTest(source):
                self.assertIn('export var h', deobfuscate_source(source, execution=ExecutionModel.module))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameAboutASelfCheck(TestBase):

    def _assert_each_still_prints(self, rows: dict[str, str]):
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_decided_check_prints_what_the_program_prints(self):
        self._assert_each_still_prints({
            source: prints for source, (prints, _) in A_CHECK_THE_INPUT_TEXT_DECIDES.items()})

    def test_a_decided_check_whose_hash_is_observed_prints_what_the_program_prints(self):
        self._assert_each_still_prints({
            source: prints
            for rows in (A_CHECK_DECIDED_WHERE_THE_HASH_IS_OBSERVED, A_CHECK_DECIDED_WHERE_THE_HASH_IS_OBSERVED_IN_ANOTHER_SPELLING)
            for source, (prints, _, _) in rows.items()
        })

    def test_a_decided_check_over_helpers_carrying_an_inserted_check_prints_what_the_program_prints(self):
        self._assert_each_still_prints({
            source: prints for source, (prints, _) in A_CHECK_DECIDED_OVER_HELPERS_CARRYING_AN_INSERTED_CHECK.items()})

    def test_a_decided_check_over_a_helper_calling_what_the_host_passed_prints_what_the_program_prints(self):
        self._assert_each_still_prints({
            source: prints
            for source, (prints, _) in A_CHECK_DECIDED_OVER_A_HELPER_CALLING_WHAT_THE_HOST_PASSED.items()
        })

    def test_a_check_left_standing_prints_what_the_program_prints(self):
        self._assert_each_still_prints(A_CHECK_THE_INPUT_TEXT_DOES_NOT_DECIDE)

    def test_a_check_the_clock_decides_prints_in_2098_what_the_program_prints_in_2098(self):
        rows = A_CHECK_THE_CLOCK_DECIDES
        self.assertEqual(
            {
                source: (
                    behavior(joined(IN_2098, source)),
                    behavior(joined(IN_2098, deobfuscate_source(source, execution=ExecutionModel.module))),
                )
                for source in rows
            },
            {source: (in_2098, in_2098) for source, (_, in_2098) in rows.items()},
        )

    def test_a_comparison_with_no_integer_prints_what_the_program_prints(self):
        self._assert_each_still_prints(A_HASH_COMPARED_WITH_NO_INTEGER)

    def test_an_exported_hash_prints_what_the_module_prints(self):
        rows = A_HASH_THE_MODULE_EXPORTS
        self.assertEqual(
            {source: before_and_after(source, module=True) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_script_kept_for_its_value_ends_on_the_value_it_ended_on(self):
        for source in A_SCRIPT_ENDING_WHERE_A_HASH_IS_DECIDED:
            with self.subTest(source):
                self.assertEqual(
                    completion_values([source]),
                    completion_values([deobfuscate_source(source, preserve_script_return=True)]),
                )


class TestASelfCheckAsksAboutAConversionOnlyWhereNothingElseStopsTheFold(TestBase):

    @staticmethod
    def _waits(source: str) -> bool:
        ast = JsParser(source).parse()
        settlement = ConversionSettlement()
        transformer = JsSelfCheckFolding()
        transformer.models = ModelCache(ast, None, settlement)
        transformer.visit(ast)
        return settlement.waiting is not None

    def test_a_line_break_check_beside_a_written_object_prototype_leaves_nothing_waiting(self):
        source = inspect.cleandoc(r'''
            var N = function () { return 1; };
            var saved = [N];
            Object.prototype.extra = 1;
            var T = function () { const R = new RegExp("\n"); return R.test(N); };
            if (T()) { console.log("tampered"); } else { console.log("clean"); }
            console.log(saved.length);
        ''')
        self.assertFalse(self._waits(source))

    def test_a_hash_guard_comparing_against_another_constant_leaves_nothing_waiting(self):
        tail = inspect.cleandoc('''
            var keep = [double];
            console.log(guarded(21), keep.length);
        ''')
        self.assertFalse(self._waits(guarded(DOUBLE, 'double', 42, DOUBLE_42 + 1, tail)))

    def test_a_hash_guard_over_a_function_kept_in_an_array_waits_for_the_settled_tree(self):
        tail = inspect.cleandoc('''
            var keep = [double];
            console.log(guarded(21), keep.length);
        ''')
        self.assertTrue(self._waits(guarded(DOUBLE, 'double', 42, DOUBLE_42, tail)))

    def test_a_lone_hash_call_whose_match_statics_are_read_leaves_nothing_waiting(self):
        self.assertFalse(self._waits(
            A_LONE_HASH_CALL_OVER_A_FUNCTION_HANDED_ON
            + r'if (/(\d+)/.test("abc 123")) { console.log("$1=" + RegExp.$1); }'
        ))

    def test_a_lone_hash_call_over_a_function_handed_on_waits_for_the_settled_tree(self):
        self.assertTrue(self._waits(A_LONE_HASH_CALL_OVER_A_FUNCTION_HANDED_ON))
