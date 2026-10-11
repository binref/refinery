"""
The two self-checks that read the source text of a function, as
`refinery.lib.scripts.js.deobfuscation.selfchecks` folds them: the line-break check and the hash
guard. Every program here is written by hand. A hash constant in a program is what Node prints for
the program's own helper run on the guarded function, so a program whose constant were wrong would
print `tampered` in Node and fail the test that reads what it prints.
"""
from __future__ import annotations

import inspect
import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import (
    completion_values,
    deobfuscate_source,
    node_executable,
)
from test.lib.scripts.js.ledger import before_and_after, each_program_still_prints

from refinery.lib.scripts.js.analysis.cache import ModelCache
from refinery.lib.scripts.js.analysis.conversions import ConversionSettlement
from refinery.lib.scripts.js.deobfuscation.selfchecks import JsSelfCheckFolding
from refinery.lib.scripts.js.parser import JsParser

#: A line-break check over the function that holds it, in the shape the obfuscator writes at the
#: start of a block, one line long.
LINE_BREAK_CHECK = (
    r'var n = function () { const t = function () { const r = new RegExp("\n"); return r["test"](n); }; '
    r'if (t()) { console.log("tampered"); } }; return n();'
)

#: The marker of a line-break check that is still in a deobfuscated file.
LINE_BREAK_MARKER = 'new RegExp('

#: A line-break check over a function of its own, written as the test of an `if` the obfuscator
#: inserts.
INSERTED_LINE_BREAK_CHECK = (
    r'function () { var n = function () { const t = function () { const r = new RegExp("\n"); return r.test(n); }; '
    'return t(); }; return n(); }()'
)

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
    A program wrapped in the older hash guard, with *helpers* and *program*, comparing to
    *constant*.
    """
    return (
        F'{prefix}(function () {{\n{helpers}{program}'
        '  var h = hashText(textOf(program), 25);\n'
        F'  if (h == {constant}) {{ return program.apply(this, arguments); }} else {{ console.log("tampered"); }}\n'
        '})();\n'
    )


def inserted_at_the_start_of_the_hash(statement: str) -> str:
    """
    The older hash helpers with *statement* inserted at the start of the hash.
    """
    return OLD_HELPERS.replace('function hashText(str, seed) { ', F'function hashText(str, seed) {{ {statement}')


def inserted_before_the_hash_returns(statement: str) -> str:
    """
    The older hash helpers with *statement* inserted in front of the `return` of the hash.
    """
    return OLD_HELPERS.replace(_HASH_RETURN, F'{statement}{_HASH_RETURN}')


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
    (
        NEW_HELPERS
        + DOUBLE
        + '\nfunction guarded() { guarded.memo || (guarded.memo = hashOf(double, 42)); return double(...arguments); }\n'
        + 'console.log(guarded(21));\n'
    ): ('42\n', 'hashOf('),
    wrapped(PROGRAM_25, inserted_at_the_start_of_the_hash(F'if ({INSERTED_LINE_BREAK_CHECK}) {{ console.log("tampered"); }} ')): (
        'ran\n', str(PROGRAM_25)),
    inspect.cleandoc(r'''
        var N = function () { return 1; };
        var saved = [N];
        var T = function () { const R = new RegExp("\n"); return R.test(N); };
        if (T()) { console.log("tampered"); } else { console.log("clean"); }
        console.log(saved.length);
    '''): ('clean\n1\n', LINE_BREAK_MARKER),
    guarded(DOUBLE, 'double', 42, DOUBLE_42, 'var keep = [double];\nconsole.log(guarded(21), guarded(4), keep.length);\n'): (
        '42 8 1\n', str(DOUBLE_42)),
    guarded(DOUBLE, 'double', 42, DOUBLE_42, 'function use(f) { return [f]; }\nconsole.log(guarded(21), use(double).length);\n'): (
        '42 1\n', str(DOUBLE_42)),
    (
        r'(function (...m) { m.length = 0; m[9] = function () { const t = function () { const r = new RegExp("\n"); '
        r'return r.test(m[9]); }; if (t()) { console.log("tampered"); } }; return m[9](); })();' '\n'
        'console.log("ran");\n'
    ): ('ran\n', LINE_BREAK_MARKER),
}

#: Programs whose hash guard the input text decides while the program may read the match statics
#: of `RegExp` that the hash sets, mapped to what Node prints, to the hash call, which the
#: deobfuscation keeps for them although the comparison is gone, and to the constant compared.
A_CHECK_DECIDED_WHERE_THE_HASH_IS_OBSERVED = {
    guarded(
        DOUBLE, 'double', 42, DOUBLE_42,
        'if (/(\\d+)/.test("abc 123")) { guarded(1); console.log("$1=" + globalThis.RegExp.$1); }\n',
    ): ('$1=\n', 'hashOf(double, 42)', str(DOUBLE_42)),
    guarded(
        DOUBLE,
        'double',
        42,
        DOUBLE_42,
        'if (/(\\d+)/.test("abc 123")) { guarded(1); console.log("$1=" + new RegExp("a").constructor.$1); }\n',
    ): (
        '$1=\n',
        'hashOf(double, 42)',
        str(DOUBLE_42),
    ),
    (
        wrapped(PROGRAM_25, inserted_at_the_start_of_the_hash(F'if ({INSERTED_LINE_BREAK_CHECK}) {{ console.log("tampered"); }} '))
        + 'if (/(\\d+)/.test("abc 123")) { console.log("$1=" + RegExp.$1); }\n'
    ): (
        'ran\n$1=123\n',
        'hashText(textOf(program), 25)',
        str(PROGRAM_25),
    ),
}

#: Programs wrapped in the older hash guard whose helpers carry a check the obfuscator inserted,
#: mapped to what Node prints and to the constant compared. The deobfuscation keeps the hash call,
#: which runs the inserted check where it ran, although the comparison is gone.
A_CHECK_DECIDED_OVER_HELPERS_CARRYING_AN_INSERTED_CHECK = {
    wrapped(PROGRAM_READING_TRIPPED_25, CONTEXT_HELPERS, PROGRAM_READING_TRIPPED, 'var ctx = globalThis;\n'): (
        'ran string\n', str(PROGRAM_READING_TRIPPED_25)),
    wrapped(PROGRAM_25, CRASH_HELPERS, PROGRAM, 'var ctx = globalThis;\n'): ('ran\n', str(PROGRAM_25)),
    wrapped(PROGRAM_READING_A_KEY_25, DATED_HELPERS, PROGRAM_READING_A_KEY): (
        'ran\n', str(PROGRAM_READING_A_KEY_25)),
    wrapped(
        PROGRAM_25,
        OLD_HELPERS.replace('function textOf(x) { ', 'function textOf(x) { if (Date.now() > 0) { console.log("dated"); } '),
    ): ('dated\nran\n', str(PROGRAM_25)),
}

SET_A_LINE_BREAK = r'function () { return "a\nb"; }'


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


#: Programs whose self-check the input text does not decide, or which stands where its declaration
#: is no statement of its own, mapped to what Node prints for each and to the text of the check,
#: which the deobfuscation still holds.
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
    checked_by_name(F'var o = new N(); o.constructor.toString = {SET_A_LINE_BREAK}; ', 'if (new.target) { return; } '): (
        'tampered\n', LINE_BREAK_MARKER),
    checked_by_name('new N(); ', F'if (new.target) {{ new.target.toString = {SET_A_LINE_BREAK}; return; }} '): (
        'tampered\n', LINE_BREAK_MARKER),
    checked_by_name(
        F'var B = N.bind(null); new B().constructor.toString = {SET_A_LINE_BREAK}; ', 'if (new.target) { return; } '
    ): ('tampered\n', LINE_BREAK_MARKER),
    checked_by_name(F'(function (s, v) {{ v.toString = {SET_A_LINE_BREAK}; }})`${{N}}`; '): (
        'tampered\n', LINE_BREAK_MARKER),
    checked_by_name(F'function g() {{ g.caller.toString = {SET_A_LINE_BREAK}; }} ', 'g(); '): (
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
    wrapped(PROGRAM_25, inserted_at_the_start_of_the_hash('if (Date.now() < 0) { seed = 1; } '), PROGRAM): (
        'ran\n', str(PROGRAM_25)),
    wrapped(PROGRAM_25, inserted_at_the_start_of_the_hash('if (Date.now() < 0) { return 1; } '), PROGRAM): (
        'ran\n', str(PROGRAM_25)),
    wrapped(PROGRAM_25, inserted_at_the_start_of_the_hash('if (Date.now() < 0) { imul = null; } '), PROGRAM): (
        'ran\n', str(PROGRAM_25)),
    wrapped(PROGRAM_25, inserted_at_the_start_of_the_hash('if (new.target) { console.log("constructed"); } '), PROGRAM): (
        'ran\n', str(PROGRAM_25)),
    wrapped(
        PROGRAM_25,
        inserted_at_the_start_of_the_hash('if (Date.now() < 0) { String.prototype.charCodeAt = function () { return 0; }; } '),
        PROGRAM,
    ): ('ran\n', str(PROGRAM_25)),
    wrapped(PROGRAM_25, inserted_before_the_hash_returns('if (Date.now() > 0) { with ({}) { h2 = 0; } } '), PROGRAM): (
        'tampered\n', str(PROGRAM_25)),
    wrapped(PROGRAM_25, inserted_before_the_hash_returns('if (Date.now() > 0) { eval("h2 = 0"); } '), PROGRAM): (
        'tampered\n', str(PROGRAM_25)),
    wrapped(PROGRAM_25, inserted_before_the_hash_returns('if (Date.now() > 0) { function h2() {} } '), PROGRAM): (
        'tampered\n', str(PROGRAM_25)),
    checked(LINE_BREAK_CHECK.replace('const t = function ()', 'const t = async function ()')): (
        'tampered\nran\n',
        LINE_BREAK_MARKER,
    ),
    checked(LINE_BREAK_CHECK.replace('const t = function ()', 'const t = async () =>')): (
        'tampered\nran\n',
        LINE_BREAK_MARKER,
    ),
    checked(LINE_BREAK_CHECK.replace('const t = function ()', 'const t = function* ()')): (
        'tampered\nran\n',
        LINE_BREAK_MARKER,
    ),
    (
        '(function () { var N; var keep = (N = function () { '
        r'const T = function () { const R = new RegExp("\n"); return R["test"](N); }; '
        'if (T()) { console.log("tampered"); } else { console.log("fine"); } }); '
        F'keep.toString = {SET_A_LINE_BREAK}; return N(); }})();\n'
    ): (
        'tampered\n',
        LINE_BREAK_MARKER,
    ),
    guarded(DOUBLE, 'double', 42, DOUBLE_42, 'console.log(guarded(21));\n').replace('guarded.memo', 'guarded.name'): (
        'tampered\nundefined\n',
        str(DOUBLE_42),
    ),
    guarded(DOUBLE, 'double', 42, DOUBLE_42, 'console.log(guarded(21));\n').replace('guarded.memo', 'guarded.call'): (
        'tampered\nundefined\n',
        str(DOUBLE_42),
    ),
    guarded(
        DOUBLE,
        'double',
        42,
        DOUBLE_42,
        'try { console.log(guarded(21)); } catch (e) { console.log(e.constructor.name); }\n',
        helpers=NEW_HELPERS.replace('var imul = Math["imul"] || MathImulPolyfill;\n', '').replace('imul(', 'IMUL('),
    ): (
        'ReferenceError\n',
        str(DOUBLE_42),
    ),
    guarded(
        DOUBLE,
        'double',
        42,
        DOUBLE_42,
        'try { console.log(guarded(21)); } catch (e) { console.log(e.constructor.name); }\n',
        helpers=NEW_HELPERS.replace('return hashText(fnStringed, seed)', 'return HASH(fnStringed, seed)'),
    ): (
        'ReferenceError\n',
        str(DOUBLE_42),
    ),
    (
        NEW_HELPERS
        + DOUBLE
        + '\nfunction guarded() { for (var h = guarded.memo || (guarded.memo = hashOf(double, 42)); ; ) { '
        + F'if (h === {DOUBLE_42}) {{ return double(...arguments); }} else {{ console.log("tampered"); }} break; }} }}\n'
        + 'if (/(\\d+)/.test("abc 123")) { console.log(guarded(21)); console.log("$1=" + RegExp.$1); }\n'
    ): (
        '42\n$1=\n',
        str(DOUBLE_42),
    ),
}

#: A hash guard over a name the module exports, mapped to what Node prints for the module. An
#: importer reads the name, so its declaration stays.
A_HASH_THE_MODULE_EXPORTS = {
    (
        NEW_HELPERS
        + DOUBLE
        + '\nexport var h = hashOf(double, 42);\n'
        + F'if (h === {DOUBLE_42}) {{ console.log(double(21)); }} else {{ console.log("tampered"); }}\n'
    ): '42\n',
}

#: Programs whose comparison constant or seed is not a finite number, mapped to what Node prints.
A_HASH_COMPARED_WITH_NO_INTEGER = {
    'function f(a) { var r = Math.min(a, 1 / 0); if (r === 0) { return 1; } return 2; }\n'
    'console.log(f(process.argv.length));\n': '2\n',
    'function g(a, b) { return a + b; }\n'
    'function f(a) { var r = g(a, 1e999); if (r === 5) { return 1; } return 2; }\n'
    'console.log(f(3));\n': '2\n',
}


#: A hash call standing alone over helpers that carry nothing, beside a call that hands the function
#: it hashes on to code of its own.
A_LONE_HASH_CALL_OVER_A_FUNCTION_HANDED_ON = (
    '(function () {\n' + OLD_HELPERS + PROGRAM
    + '  hashText(textOf(program), 25);\n'
    + '  keep(program);\n'
    + '})();\n'
    + 'function keep(f) { return [f]; }\n'
)

#: Scripts in which a hash the self-check folding decides stands where it would set the value the
#: script ends on: a hash call standing last, and the declaration of a hash a guard compares behind
#: which no statement leaves a value.
A_SCRIPT_ENDING_WHERE_A_HASH_IS_DECIDED = (
    OLD_HELPERS + PROGRAM + 'hashText(textOf(program), 25);\n',
    (
        'var ctx = globalThis;\n' + CONTEXT_HELPERS + PROGRAM_READING_TRIPPED
        + 'var h = hashText(textOf(program), 25);\n'
        + F'function run() {{ if (h == {PROGRAM_READING_TRIPPED_25}) {{ return program(); }} else {{ console.log("tampered"); }} }}\n'
    ),
)


class TestTheCheckTheInputTextDecidesIsGone(TestBase):

    def test_the_deobfuscation_no_longer_holds_the_check(self):
        for source, (_, marker) in A_CHECK_THE_INPUT_TEXT_DECIDES.items():
            with self.subTest(source):
                self.assertNotIn(marker, deobfuscate_source(source, module=True))

    def test_the_hash_call_stays_where_its_match_statics_may_be_read(self):
        for source, (_, kept, constant) in A_CHECK_DECIDED_WHERE_THE_HASH_IS_OBSERVED.items():
            with self.subTest(source):
                text = deobfuscate_source(source, module=True)
                self.assertIn(kept, text)
                self.assertNotIn(constant, text)

    def test_the_hash_call_stays_where_its_helpers_carry_an_inserted_check(self):
        for source, (_, constant) in A_CHECK_DECIDED_OVER_HELPERS_CARRYING_AN_INSERTED_CHECK.items():
            with self.subTest(source):
                text = deobfuscate_source(source, module=True)
                self.assertIn('hashText(textOf(program), 25);', text)
                self.assertNotIn(constant, text)

    def test_a_hash_call_nothing_reads_goes_once_its_inserted_check_is_decided(self):
        source = wrapped(
            PROGRAM_25,
            inserted_at_the_start_of_the_hash(F'if ({INSERTED_LINE_BREAK_CHECK}) {{ console.log("tampered"); }} '),
        )
        self.assertNotIn('hashText', deobfuscate_source(source, module=True))


class TestTheCheckTheInputTextDoesNotDecideStays(TestBase):

    def test_the_deobfuscation_still_holds_the_check(self):
        for source, (_, marker) in A_CHECK_THE_INPUT_TEXT_DOES_NOT_DECIDE.items():
            with self.subTest(source):
                self.assertIn(marker, deobfuscate_source(source, module=True))

    def test_the_deobfuscation_still_exports_the_hash(self):
        for source in A_HASH_THE_MODULE_EXPORTS:
            with self.subTest(source):
                self.assertIn('export var h', deobfuscate_source(source, module=True))


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
            source: prints for source, (prints, _, _) in A_CHECK_DECIDED_WHERE_THE_HASH_IS_OBSERVED.items()})

    def test_a_decided_check_over_helpers_carrying_an_inserted_check_prints_what_the_program_prints(self):
        self._assert_each_still_prints({
            source: prints for source, (prints, _) in A_CHECK_DECIDED_OVER_HELPERS_CARRYING_AN_INSERTED_CHECK.items()})

    def test_a_check_left_standing_prints_what_the_program_prints(self):
        self._assert_each_still_prints({
            source: prints for source, (prints, _) in A_CHECK_THE_INPUT_TEXT_DOES_NOT_DECIDE.items()})

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
    """
    Asking whether a function handed on converts to its written text notes the tree the question was
    refused on, and the run settles that tree and runs again. The self-check pass asks only where
    nothing else stands in the way of the fold, so a check it cannot decide anyway costs no run.
    """

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
        tail = 'var keep = [double];\nconsole.log(guarded(21), keep.length);\n'
        self.assertFalse(self._waits(guarded(DOUBLE, 'double', 42, DOUBLE_42 + 1, tail)))

    def test_a_hash_guard_over_a_function_kept_in_an_array_waits_for_the_settled_tree(self):
        tail = 'var keep = [double];\nconsole.log(guarded(21), keep.length);\n'
        self.assertTrue(self._waits(guarded(DOUBLE, 'double', 42, DOUBLE_42, tail)))

    def test_a_lone_hash_call_whose_match_statics_are_read_leaves_nothing_waiting(self):
        self.assertFalse(self._waits(
            A_LONE_HASH_CALL_OVER_A_FUNCTION_HANDED_ON
            + 'if (/(\\d+)/.test("abc 123")) { console.log("$1=" + RegExp.$1); }\n'
        ))

    def test_a_lone_hash_call_over_a_function_handed_on_waits_for_the_settled_tree(self):
        self.assertTrue(self._waits(A_LONE_HASH_CALL_OVER_A_FUNCTION_HANDED_ON))
