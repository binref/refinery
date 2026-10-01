"""
The two self-checks that read the source text of a function, as
`refinery.lib.scripts.js.deobfuscation.selfchecks` folds them: the line-break check and the hash
guard. Every program here is written by hand. A hash constant in a program is what Node prints for
the program's own helper run on the guarded function, so a program whose constant were wrong would
print `tampered` in Node and fail the test that reads what it prints.
"""
from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import deobfuscate_source, node_executable
from test.lib.scripts.js.ledger import before_and_after, each_program_still_prints

#: A line-break check over the function that holds it, in the shape the obfuscator writes at the
#: start of a block, one line long.
LINE_BREAK_CHECK = (
    r'var n = function () { const t = function () { const r = new RegExp("\n"); return r["test"](n); }; '
    r'if (t()) { console.log("tampered"); } }; return n();'
)

#: The marker of a line-break check that is still in a deobfuscated file.
LINE_BREAK_MARKER = 'new RegExp('

#: The hash helpers, in the newer form: the fallback multiplication, the cyrb53 hash, and the helper
#: that hashes a function's text with spaces, line breaks and `;,{}().[]` removed.
NEW_HELPERS = (
    'function MathImulPolyfill(opA, opB) { opB |= 0; var result = (opA & 0x003fffff) * opB; '
    'if (opA & 0xffc00000) result += (opA & 0xffc00000) * opB | 0; return result | 0; }\n'
    'var imul = Math["imul"] || MathImulPolyfill;\n'
    'function hashText(str, seed) { var h1 = 0xdeadbeef ^ seed; var h2 = 0x41c6ce57 ^ seed; '
    'for (var i = 0, ch; i < str.length; i++) { ch = str.charCodeAt(i); h1 = imul(h1 ^ ch, 2654435761); '
    'h2 = imul(h2 ^ ch, 1597334677); } h1 = imul(h1 ^ (h1 >>> 16), 2246822507) ^ imul(h2 ^ (h2 >>> 13), 3266489909); '
    'h2 = imul(h2 ^ (h2 >>> 16), 2246822507) ^ imul(h1 ^ (h1 >>> 13), 3266489909); '
    'return 4294967296 * (2097151 & h2) + (h1 >>> 0); }\n'
    r'function hashOf(fnObject, seed, regex = new RegExp(" |\\n|;|,|\\{|\\}|\\(|\\)|\\.|\\[|\\]", "g")) '
    '{ var fnStringed = fnObject["toString"]()["replace"](regex, ""); return hashText(fnStringed, seed); }\n'
)

#: The newer helpers with one shift of the hash changed, which computes another hash.
LOOK_ALIKE_HELPERS = NEW_HELPERS.replace('h1 >>> 16), 2246822507) ^', 'h1 >>> 15), 2246822507) ^')

#: The hash helpers in the older form, indented for the function the older guard wraps a program in.
OLD_HELPERS = (
    '  var imul = Math.imul || function (opA, opB) { opB |= 0; var result = (opA & 4194303) * opB; '
    'if (opA & 4290772992) result += (opA & 4290772992) * opB | 0; return result | 0; };\n'
    '  function hashText(str, seed) { var h1 = 0xdeadbeef ^ seed; var h2 = 0x41c6ce57 ^ seed; '
    'for (var i = 0, ch; i < str.length; i++) { ch = str.charCodeAt(i); h1 = imul(h1 ^ ch, 2654435761); '
    'h2 = imul(h2 ^ ch, 1597334677); } h1 = imul(h1 ^ (h1 >>> 16), 2246822507) ^ imul(h2 ^ (h2 >>> 13), 3266489909); '
    'h2 = imul(h2 ^ (h2 >>> 16), 2246822507) ^ imul(h1 ^ (h1 >>> 13), 3266489909); '
    'return 4294967296 * (2097151 & h2) + (h1 >>> 0); }\n'
    r'  function textOf(x) { return x.toString().replace(/ |\n|;|,|\{|\}|\(|\)|\.|\[|\]/g, ""); }' '\n'
)

_HASH_RETURN = 'return 4294967296 * (2097151 & h2) + (h1 >>> 0); }'

#: The older helpers with a check of the host inserted into the hash, observable through `tripped`.
CONTEXT_HELPERS = OLD_HELPERS.replace(
    _HASH_RETURN,
    F'if (!ctx["missingContext"]) {{ tripped = "yes"; }} {_HASH_RETURN}',
)

#: The older helpers with a check of the host inserted into the hash that loops without end where
#: it trips.
CRASH_HELPERS = OLD_HELPERS.replace(
    _HASH_RETURN,
    'if (!ctx["process"]) { var crashVar = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"; '
    F'while (true) {{ crashVar = crashVar; if (!crashVar) break; }} }} {_HASH_RETURN}',
)

#: The older helpers with a date check inserted into the hash.
DATED_HELPERS = OLD_HELPERS.replace(
    'function hashText(str, seed) { ',
    'function hashText(str, seed) { if (Date.now() < 946684800000) { console.log("early"); } ',
)

DOUBLE = 'function double(x) { return x * 2; }'
SMILE = 'function smile(x) { return x + "' + chr(0x1F600) + '"; }'
GREET = 'function greet(x) { return `hi ${x}`; }'
NAME_OF = 'function nameOf(x) { return x["name"]; }'
PROGRAM = '  function program() { console.log("ran"); }\n'
PROGRAM_READING_A_KEY = '  function program() { console.log({ name: "ran" }["name"]); }\n'
PROGRAM_READING_TRIPPED = '  function program() { console.log("ran", typeof tripped); }\n'

DOUBLE_42 = 8332086338560561
SMILE_7 = 6376619314661907
GREET_3 = 4670964258068317
NAME_OF_5 = 6806156106331032
LOOK_ALIKE_DOUBLE_42 = 1155131416700091
PROGRAM_25 = 4345407897497152
PROGRAM_READING_A_KEY_25 = 4939227658243236
PROGRAM_READING_TRIPPED_25 = 7786884700990675


def guarded(subject: str, name: str, seed: int, constant: int, tail: str, helpers: str = NEW_HELPERS) -> str:
    """
    A program holding *helpers*, the function *subject* named *name*, and the newer hash guard
    over it with *seed* and *constant*, followed by *tail*.
    """
    return (
        F'{helpers}{subject}\n'
        F'function guarded() {{ var h = guarded.memo || (guarded.memo = hashOf({name}, {seed})); '
        F'if (h === {constant}) {{ return {name}(...arguments); }} else {{ console.log("tampered"); }} }}\n'
        F'{tail}'
    )


def wrapped(constant: int, helpers: str = OLD_HELPERS, program: str = PROGRAM, prefix: str = '') -> str:
    """
    A program wrapped in the older hash guard, with *helpers* and *program*, comparing to *constant*.
    """
    return (
        F'{prefix}(function () {{\n{helpers}{program}'
        '  var h = hashText(textOf(program), 25);\n'
        F'  if (h == {constant}) {{ return program.apply(this, arguments); }} else {{ console.log("tampered"); }}\n'
        '})();\n'
    )


def checked(statement: str = LINE_BREAK_CHECK, tail: str = 'console.log("ran");\n') -> str:
    """
    A program running the line-break check *statement* in a function of its own, then *tail*.
    """
    return F'(function () {{ {statement} }})();\n{tail}'


#: Programs whose self-check the input text decides, mapped to what Node prints for each and to the
#: text of the check, which the deobfuscation no longer holds.
A_CHECK_THE_INPUT_TEXT_DECIDES = {
    checked(): ('ran\n', LINE_BREAK_MARKER),
    (
        'if (function () { var n = function () { const t = function () { '
        r'const r = new RegExp("\n"); return r.test(n); }; return t(); }; return n(); }()) '
        '{ console.log("tampered"); }\nconsole.log("ran");\n'
    ): ('ran\n', LINE_BREAK_MARKER),
    (
        F'function f(k) {{ for (let i = 0; i < k; i++) {{ (function () {{ {LINE_BREAK_CHECK} }})(); }} return k; }}\n'
        'console.log(f(3));\n'
    ): ('3\n', LINE_BREAK_MARKER),
    checked(
        r'var x = function () { const y = function () { const y = new RegExp("\n"); return y.test(x); }; '
        'if (y()) { console.log("tampered"); } }; return x();'
    ): ('ran\n', LINE_BREAK_MARKER),
    (
        'if (/(\\d+)/.test("abc 123")) { (function () { ' + LINE_BREAK_CHECK + ' })(); '
        'console.log("$1=" + RegExp.$1); }\n'
    ): ('$1=123\n', LINE_BREAK_MARKER),
    guarded(DOUBLE, 'double', 42, DOUBLE_42, 'console.log(guarded(21), guarded(4));\n'): (
        '42 8\n', str(DOUBLE_42)),
    guarded(SMILE, 'smile', 7, SMILE_7, 'console.log(guarded("a"));\n'): (
        'a' + chr(0x1F600) + '\n', str(SMILE_7)),
    guarded(GREET, 'greet', 3, GREET_3, 'console.log(guarded("you"));\n'): (
        'hi you\n', str(GREET_3)),
    guarded(NAME_OF, 'nameOf', 5, NAME_OF_5, 'console.log(guarded({ name: "you" }));\n'): (
        'you\n', str(NAME_OF_5)),
    wrapped(PROGRAM_25): ('ran\n', str(PROGRAM_25)),
}

#: Programs whose hash guard the input text decides while the program may read the match statics
#: of `RegExp` that the hash sets, mapped to what Node prints and to the hash call, which the
#: deobfuscation keeps for them although the comparison is gone.
A_CHECK_DECIDED_WHERE_THE_HASH_IS_OBSERVED = {
    guarded(
        DOUBLE, 'double', 42, DOUBLE_42,
        'if (/(\\d+)/.test("abc 123")) { guarded(1); console.log("$1=" + globalThis.RegExp.$1); }\n',
    ): ('$1=\n', 'hashOf(double, 42)'),
}

_SET_A_LINE_BREAK = r'function () { return "a\nb"; }'


def checked_by_name(route: str, prefix: str = '') -> str:
    """
    A line-break check over the function named `N`, with *route* run after `N` is declared and
    *prefix* at the start of its body.
    """
    return (
        '(function () { var N = function () { '
        + prefix
        + r'const T = function () { const R = new RegExp("\n"); return R["test"](N); }; '
        'if (T()) { console.log("tampered"); } else { console.log("fine"); } }; '
        + route
        + 'return N(); })();\n'
    )


#: Programs whose self-check the input text does not decide, mapped to what Node prints for each
#: and to the text of the check, which the deobfuscation still holds.
A_CHECK_THE_INPUT_TEXT_DOES_NOT_DECIDE = {
    checked(
        'var n = function () {\nconst t = function () { const r = new RegExp("\\n"); return r.test(n); }; '
        'if (t()) { console.log("tampered"); } }; return n();'
    ): ('tampered\nran\n', LINE_BREAK_MARKER),
    guarded(
        DOUBLE, 'double', 42, DOUBLE_42,
        'if (/(\\d+)/.test("abc 123")) { guarded(1); var R = /x/.constructor; console.log("$1=" + R.$1); }\n',
    ): ('$1=\n', str(DOUBLE_42)),
    'RegExp.prototype.test = function () { return true; };\n' + checked(): ('tampered\nran\n', LINE_BREAK_MARKER),
    r'Function.prototype.toString = function () { return "\n"; };' '\n' + checked(): (
        'tampered\nran\n', LINE_BREAK_MARKER),
    r'Object.prototype[Symbol.toPrimitive] = function () { return "\n"; };' '\n' + checked(): (
        'tampered\nran\n', LINE_BREAK_MARKER),
    checked(
        r'var n = function () { const t = function () { const r = new RegExp("\n"); return r.test(n); }; '
        r'if (t()) { console.log("tampered"); } }; n.toString = function () { return "\n"; }; return n();'
    ): ('tampered\nran\n', LINE_BREAK_MARKER),
    'var RegExp = function () { return { test: function () { return true; } }; };\n' + checked(): (
        'tampered\nran\n', LINE_BREAK_MARKER),
    'function patch(R) { R.prototype.test = function () { return true; }; }\npatch(RegExp);\n' + checked(): (
        'tampered\nran\n', LINE_BREAK_MARKER),
    '(function (R) { R.prototype.test = function () { return true; }; })(RegExp);\n' + checked(): (
        'tampered\nran\n', LINE_BREAK_MARKER),
    'Reflect.set(RegExp.prototype, "test", function () { return true; });\n' + checked(): (
        'tampered\nran\n', LINE_BREAK_MARKER),
    'globalThis.RegExp.prototype.test = function () { return true; };\n' + checked(): (
        'tampered\nran\n', LINE_BREAK_MARKER),
    (
        'globalThis.Object.prototype[Symbol.toPrimitive] = function () { return "a" + String.fromCharCode(10); };\n'
        + checked()
    ): ('tampered\nran\n', LINE_BREAK_MARKER),
    checked(
        r'var n = function m() { m.toString = function () { return "\n"; }; '
        r'const t = function () { const r = new RegExp("\n"); return r.test(n); }; '
        'if (t()) { console.log("tampered"); } }; return n();'
    ): ('tampered\nran\n', LINE_BREAK_MARKER),
    (
        r'class X { static [Symbol.hasInstance](v) { v.toString = function () { return "\n"; }; return false; } }'
        '\n' + checked(LINE_BREAK_CHECK.replace('return n();', 'n instanceof X; return n();'))
    ): ('tampered\nran\n', LINE_BREAK_MARKER),
    (
        'var N = function () {};\n'
        r'var T = function () { const R = new RegExp("\n"); return R.test(N); };' '\n'
        'globalThis["N"] = function () {\n};\n'
        'if (T()) { console.log("tampered"); } else { console.log("clean"); }\n'
    ): ('clean\n', LINE_BREAK_MARKER),
    checked_by_name(F'var o = new N(); o.constructor.toString = {_SET_A_LINE_BREAK}; ', 'if (new.target) { return; } '): (
        'tampered\n', LINE_BREAK_MARKER),
    checked_by_name('new N(); ', F'if (new.target) {{ new.target.toString = {_SET_A_LINE_BREAK}; return; }} '): (
        'tampered\n', LINE_BREAK_MARKER),
    checked_by_name(
        F'var B = N.bind(null); new B().constructor.toString = {_SET_A_LINE_BREAK}; ', 'if (new.target) { return; } '
    ): ('tampered\n', LINE_BREAK_MARKER),
    checked_by_name(F'(function (s, v) {{ v.toString = {_SET_A_LINE_BREAK}; }})`${{N}}`; '): (
        'tampered\n', LINE_BREAK_MARKER),
    checked_by_name(F'function g() {{ g.caller.toString = {_SET_A_LINE_BREAK}; }} ', 'g(); '): (
        'tampered\n', LINE_BREAK_MARKER),
    guarded(DOUBLE, 'double', 42, DOUBLE_42 + 1, 'console.log(guarded(21));\n'): (
        'tampered\nundefined\n', str(DOUBLE_42 + 1)),
    guarded(DOUBLE, 'double', 42, DOUBLE_42, 'console.log(guarded(21), typeof guarded.memo);\n'): (
        '42 number\n', str(DOUBLE_42)),
    guarded(DOUBLE, 'double', 42, DOUBLE_42, 'console.log(guarded(21), Object.keys(guarded).length);\n'): (
        '42 1\n', str(DOUBLE_42)),
    guarded(
        DOUBLE, 'double', 42, LOOK_ALIKE_DOUBLE_42, 'console.log(guarded(21));\n', helpers=LOOK_ALIKE_HELPERS
    ): ('42\n', str(LOOK_ALIKE_DOUBLE_42)),
    guarded(DOUBLE, 'double', 42, DOUBLE_42, 'console.log(guarded(21));\n', helpers=LOOK_ALIKE_HELPERS): (
        'tampered\nundefined\n', str(DOUBLE_42)),
    'String.prototype.replace = function () { return "x"; };\n' + guarded(
        DOUBLE, 'double', 42, DOUBLE_42, 'console.log(guarded(21));\n'
    ): ('tampered\nundefined\n', str(DOUBLE_42)),
    'delete Math.imul;\n' + guarded(
        DOUBLE, 'double', 42, DOUBLE_42, 'console.log(guarded(21));\n',
        helpers=NEW_HELPERS.replace('|| MathImulPolyfill', '|| function (a, b) { return 0; }'),
    ): ('tampered\nundefined\n', str(DOUBLE_42)),
    (
        NEW_HELPERS + DOUBLE + '\n'
        F'function guarded() {{ if (h === {DOUBLE_42}) {{ return double(...arguments); }} '
        'else { console.log("tampered"); } var h = guarded.memo || (guarded.memo = hashOf(double, 42)); }\n'
        'console.log(guarded(21));\n'
    ): ('tampered\nundefined\n', str(DOUBLE_42)),
    '"use strict";\n' + guarded(
        DOUBLE, 'double', 42, DOUBLE_42,
        'Object.freeze(guarded);\ntry { console.log(guarded(21)); } catch (e) { console.log(e.constructor.name); }\n',
    ): ('TypeError\n', str(DOUBLE_42)),
    wrapped(PROGRAM_25 + 1): ('tampered\n', str(PROGRAM_25 + 1)),
    wrapped(PROGRAM_READING_TRIPPED_25, CONTEXT_HELPERS, PROGRAM_READING_TRIPPED, 'var ctx = globalThis;\n'): (
        'ran string\n', str(PROGRAM_READING_TRIPPED_25)),
    wrapped(PROGRAM_25, CRASH_HELPERS, PROGRAM, 'var ctx = globalThis;\n'): ('ran\n', str(PROGRAM_25)),
}

#: Programs whose comparison constant or seed is not a finite number, mapped to what Node prints.
A_HASH_COMPARED_WITH_NO_INTEGER = {
    'function f(a) { var r = Math.min(a, 1 / 0); if (r === 0) { return 1; } return 2; }\n'
    'console.log(f(process.argv.length));\n': '2\n',
    'function g(a, b) { return a + b; }\n'
    'function f(a) { var r = g(a, 1e999); if (r === 5) { return 1; } return 2; }\n'
    'console.log(f(3));\n': '2\n',
}


class TestTheCheckTheInputTextDecidesIsGone(TestBase):

    def test_the_deobfuscation_no_longer_holds_the_check(self):
        for source, (_, marker) in A_CHECK_THE_INPUT_TEXT_DECIDES.items():
            with self.subTest(source):
                self.assertNotIn(marker, deobfuscate_source(source, module=True))

    def test_the_hash_call_stays_where_its_match_statics_may_be_read(self):
        for source, (_, kept) in A_CHECK_DECIDED_WHERE_THE_HASH_IS_OBSERVED.items():
            with self.subTest(source):
                text = deobfuscate_source(source, module=True)
                self.assertIn(kept, text)
                self.assertNotIn(str(DOUBLE_42), text)


class TestTheCheckTheInputTextDoesNotDecideStays(TestBase):

    def test_the_deobfuscation_still_holds_the_check(self):
        for source, (_, marker) in A_CHECK_THE_INPUT_TEXT_DOES_NOT_DECIDE.items():
            with self.subTest(source):
                self.assertIn(marker, deobfuscate_source(source, module=True))


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
            source: prints for source, (prints, _) in A_CHECK_DECIDED_WHERE_THE_HASH_IS_OBSERVED.items()})

    def test_a_check_left_standing_prints_what_the_program_prints(self):
        self._assert_each_still_prints({
            source: prints for source, (prints, _) in A_CHECK_THE_INPUT_TEXT_DOES_NOT_DECIDE.items()})

    def test_a_comparison_with_no_integer_prints_what_the_program_prints(self):
        self._assert_each_still_prints(A_HASH_COMPARED_WITH_NO_INTEGER)
