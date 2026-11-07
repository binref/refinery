"""
Every unicode escape in this module is assembled from `chr(92)`, mostly through `ESCAPED[XXXX]`: an
escape typed into a Python string is resolved by Python, and Node then sees the character instead of
the escape. Every table is checked for the backslash it must carry.

SECURITY: every program below is written out by this module and Node runs only those. Nothing from
`samples` may ever be handed to the engine.
"""
from __future__ import annotations

import re
import unittest

from collections.abc import Iterable

from test import TestBase
from test.lib.scripts.js.analysis.differential import behavior, deobfuscate_source, node_executable
from test.lib.scripts.js.ledger import (
    before_and_after,
    deobfuscated_behavior,
    each_program_still_prints,
    folded,
    printed,
    returned_from_a_body,
)


_A_SPELLING = re.compile(r'(ESCAPED|LITERAL)\[([0-9A-F]+)\]')

_Behavior = tuple[str, str | None]


def _an_escape(code: int) -> str:
    if code > 0xFFFF:
        return F'{chr(92)}u{{{code:X}}}'
    return F'{chr(92)}u{code:04X}'


def _spelled_with_escapes(source: str) -> str:
    def spelling(match: re.Match[str]) -> str:
        code = int(match.group(2), 16)
        return _an_escape(code) if match.group(1) == 'ESCAPED' else chr(code)
    return _A_SPELLING.sub(spelling, source)


def _programs(rows: dict[str, str]) -> dict[str, str]:
    return {_spelled_with_escapes(source): prints for source, prints in rows.items()}


def _refused(sources: Iterable[str]) -> dict[str, tuple[_Behavior, _Behavior]]:
    return {source: (('', 'SyntaxError'), ('', 'SyntaxError')) for source in sources}


def _unspelled(sources: Iterable[str]) -> list[str]:
    return [source for source in sources if chr(92) not in source]


A_BINDING_AND_A_READ_SPELLED_DIFFERENTLY = _programs({
    'var ESCAPED[0061]bc = 7; console.log(abc);': '7\n',
    'var abc = 7; console.log(ESCAPED[0061]bc);': '7\n',
    'let ESCAPED[0061]bc = 7; console.log(abc);': '7\n',
    'const abc = 7; console.log(ESCAPED[0061]bc);': '7\n',
    'function ESCAPED[0066]oo(){ return 7; } console.log(foo());': '7\n',
    'function foo(){ return 7; } console.log(ESCAPED[0066]oo());': '7\n',
    'class ESCAPED[0043]ls { m(){ return 7; } } console.log(new Cls().m());': '7\n',
    'class Cls { m(){ return 7; } } console.log(new ESCAPED[0043]ls().m());': '7\n',
    'function f(ESCAPED[0070]rm){ return prm; } console.log(f(7));': '7\n',
    'function f(prm){ return ESCAPED[0070]rm; } console.log(f(7));': '7\n',
    'var f = (ESCAPED[0070]rm) => prm; console.log(f(7));': '7\n',
    'try { throw 7; } catch (ESCAPED[0065]rr) { console.log(err); }': '7\n',
    'try { throw 7; } catch (err) { console.log(ESCAPED[0065]rr); }': '7\n',
    'for (const ESCAPED[0069]t of [7]) { console.log(it); }': '7\n',
    'var { ESCAPED[0071]q: v } = { qq: 7 }; console.log(v);': '7\n',
    'var { ESCAPED[0071]q } = { qq: 7 }; console.log(qq);': '7\n',
    'var g = function ESCAPED[0068]lp(n){ return n ? n * hlp(n - 1) : 1; }; console.log(g(4));':
        '24\n',
})


A_PROPERTY_NAME_SPELLED_WITH_AN_ESCAPE = _programs({
    returned_from_a_body(
        "return Object.keys({ ESCAPED[0061]: 1, b: 2 }).join('|');"
    ): 'a|b\n',
    returned_from_a_body('return { ESCAPED[0061]: 7 }.a;'): '7\n',
    returned_from_a_body('var o = { a: 1 }; return o.ESCAPED[0061];'): '1\n',
    returned_from_a_body("return 'q' in { ESCAPED[0071]: 1 };"): 'true\n',
    'console.log({ a: 7 }.ESCAPED[0061]);': '7\n',
    'var o = {}; o.ESCAPED[0061] = 7; console.log(o.a);': '7\n',
    'var o = { a: 1 }; delete o.ESCAPED[0061]; console.log(o.a);': 'undefined\n',
    'var abc = 7; var o = { ESCAPED[0061]bc }; console.log(o.abc);': '7\n',
    'var o = { ESCAPED[006D](){ return 7; } }; console.log(o.m());': '7\n',
    'var o = { get ESCAPED[0067]t(){ return 7; } }; console.log(o.gt);': '7\n',
    "var k = 'a'; var o = { [ESCAPED[006B]]: 7 }; console.log(o.a);": '7\n',
    'var o = { ESCAPED[005F]_proto__: null }; console.log(Object.getPrototypeOf(o));': 'null\n',
})


A_CLASS_MEMBER_NAME_SPELLED_WITH_AN_ESCAPE = _programs({
    'class C { #ESCAPED[0070]rv = 7; read(){ return this.#prv; } } console.log(new C().read());':
        '7\n',
    'class C { #prv = 7; read(){ return this.#ESCAPED[0070]rv; } } console.log(new C().read());':
        '7\n',
    'class C { #ESCAPED[006D](){ return 7; } r(){ return this.#m(); } } console.log(new C().r());':
        '7\n',
    'class C { #ESCAPED[0070]rv = 1; static has(o){ return #prv in o; } } '
    'console.log(C.has(new C()), C.has({}));': 'true false\n',
    'class C { ESCAPED[0066]ld = 7; } console.log(new C().fld);': '7\n',
    'class C { ESCAPED[006D]th(){ return 7; } } console.log(new C().mth());': '7\n',
    'class C { static ESCAPED[0073]f = 7; } console.log(C.sf);': '7\n',
    'class C { get ESCAPED[0067]t(){ return 7; } } console.log(new C().gt);': '7\n',
    'class C { ESCAPED[0063]onstructor(){ this.v = 7; } } console.log(new C().v);': '7\n',
})


A_LABEL_SPELLED_WITH_AN_ESCAPE = _programs({
    'ESCAPED[006C]bl: for (var i = 0; i < 3; i++) '
    '{ if (i) break ESCAPED[006C]bl; console.log(i); }': '0\n',
    'ESCAPED[006C]bl: for (var i = 0; i < 3; i++) { if (i) break lbl; console.log(i); }': '0\n',
    'lbl: for (var i = 0; i < 3; i++) { if (i) break ESCAPED[006C]bl; console.log(i); }': '0\n',
    'outer: for (var i = 0; i < 2; i++) { for (var j = 0; j < 2; j++) '
    "{ continue ESCAPED[006F]uter; } } console.log('done');": 'done\n',
    'lbl: { console.log(1); break ESCAPED[006C]bl; } console.log(2);': '1\n2\n',
})


AN_ESCAPED_EVAL_RUNNING_IN_ITS_CALLERS_SCOPE = _programs({
    "function f(){ var loc = 7; return ESCAPED[0065]val('loc'); } console.log(f());": '7\n',
    "function f(){ var loc = 1; ESCAPED[0065]val('loc = 9'); return loc; } console.log(f());":
        '9\n',
    "function f(){ ESCAPED[0065]val('var z = 3;'); return z; } console.log(f());": '3\n',
    "function f(){ var eval = function(){ return 'own'; }; return ESCAPED[0065]val('1'); } "
    'console.log(f());': 'own\n',
})


AN_EVAL_REACHED_INDIRECTLY_SEEING_NO_LOCAL = _programs({
    "function f(){ var loc = 7; try { return (0, ESCAPED[0065]val)('loc'); } "
    'catch (e) { return e.constructor.name; } } console.log(f());': 'ReferenceError\n',
    "function f(){ var loc = 7; try { return (0, eval)('loc'); } "
    'catch (e) { return e.constructor.name; } } console.log(f());': 'ReferenceError\n',
})


AN_INTRINSIC_NAMED_WITH_AN_ESCAPE = _programs({
    "console.log(ESCAPED[004F]bject.keys({ a: 1, b: 2 }).join(','));": 'a,b\n',
    "console.log(new ESCAPED[0046]unction('return 7')());": '7\n',
    'console.log(ESCAPED[0067]lobalThis === globalThis);': 'true\n',
    'ESCAPED[0067]lobalThis.zz = 7; console.log(zz);': '7\n',
    'console.log(ESCAPED[004A]SON.stringify({ a: 1 }));': '{"a":1}\n',
    "console.log(ESCAPED[0070]arseInt('42', 10));": '42\n',
    'console.log(ESCAPED[0053]tring.fromCharCode(65, 66));': 'AB\n',
    'console.log(ESCAPED[004E]aN !== ESCAPED[004E]aN);': 'true\n',
    'console.log(ESCAPED[0075]ndefined === void 0);': 'true\n',
    'console.log(1 / ESCAPED[0049]nfinity);': '0\n',
    'function f(){ return ESCAPED[0061]rguments[0]; } console.log(f(7));': '7\n',
})


AN_INTRINSIC_NAME_A_LOCAL_SHADOWS = _programs({
    "function f(){ var Object = { keys: function(){ return ['z']; } }; "
    'return ESCAPED[004F]bject.keys({ a: 1 })[0]; } console.log(f());': 'z\n',
})


#: A JavaScript string is a sequence of UTF-16 code units, so this key of one character above the
#: basic plane has length 2 and reads back as its surrogates 55349 and 56421, however it is spelled.
AN_ASTRAL_KEY_SPELLED_THREE_WAYS = (
    _spelled_with_escapes('Object.keys({ LITERAL[1D465]: 1 })[0]'),
    _spelled_with_escapes("Object.keys({ 'LITERAL[1D465]': 1 })[0]"),
    _spelled_with_escapes('Object.keys({ ESCAPED[1D465]: 1 })[0]'),
)


def _reading_back_the_units_of(key: str) -> str:
    return F'var k = {key}; console.log(k.length, k.charCodeAt(0), k.charCodeAt(1));'


A_NAME_WRITTEN_WITH_AN_ASTRAL_CHARACTER = _programs({
    'var LITERAL[1D465] = [0]; LITERAL[1D465][0] = 5; console.log(LITERAL[1D465][0]);': '5\n',
    'function f(LITERAL[1D465]){ return LITERAL[1D465] + globalThis.zz; } console.log(f(1));':
        'NaN\n',
    'console.log(globalThis.LITERAL[1D465]);': 'undefined\n',
    'LITERAL[1D465]: for (;;) { break LITERAL[1D465]; } console.log(1);': '1\n',
})


A_NAME_WRITTEN_WITH_THE_BRACED_ESCAPE = _programs({
    'var ESCAPED[1D465] = [0]; ESCAPED[1D465][0] = 5; console.log(ESCAPED[1D465][0]);': '5\n',
    'var LITERAL[1D465] = [0]; ESCAPED[1D465][0] = 5; console.log(LITERAL[1D465][0]);': '5\n',
    'var ESCAPED[1D465] = [0]; LITERAL[1D465][0] = 5; console.log(ESCAPED[1D465][0]);': '5\n',
})


#: Two four-digit escapes naming the surrogate halves of one character above the basic plane. They
#: combine into that character in a string literal but not in a name, where neither half is an
#: identifier character, so Node refuses both files.
THE_TWO_HALVES_OF_AN_ASTRAL_CHARACTER_WRITTEN_SEPARATELY = tuple(
    _spelled_with_escapes(source) for source in (
        'var ESCAPED[D835]ESCAPED[DC65] = [0]; console.log(1);',
        'var LITERAL[1D465] = [0]; console.log(ESCAPED[D835]ESCAPED[DC65][0]);',
    )
)


AN_ESCAPED_RESERVED_WORD_WHERE_A_VARIABLE_WAS_EXPECTED = tuple(
    _spelled_with_escapes(source) for source in (
        'var ESCAPED[0069]f = 1; console.log(2);',
        'var ESCAPED[0074]his = 1; console.log(2);',
        'console.log(ESCAPED[0074]his);',
        'class C { m(){ return ESCAPED[0073]uper.toString; } } console.log(1);',
    )
)


AN_ESCAPE_NAMING_NO_IDENTIFIER_CHARACTER = tuple(
    _spelled_with_escapes(source) for source in (
        'var aESCAPED[0020]b = 1; console.log(1);',
        'var ESCAPED[0031]a = 1; console.log(1);',
        'var aESCAPED[002B]b = 1; console.log(1);',
    )
)


AN_ESCAPE_NAMING_NO_CODE_POINT = tuple(
    _spelled_with_escapes(source) for source in (
        'var aESCAPED[110000] = 1; console.log(1);',
        F'var a{chr(92)}u00 = 1; console.log(1);',
        F'var a{chr(92)}uZZZZ = 1; console.log(1);',
        F'var a{chr(92)}u{{61 = 1; console.log(1);',
    )
)


#: A program spelling `get` or `set` with an escape where an accessor's name follows it. A terminal
#: word of the grammar is matched by the characters typed, never by an escape, so no engine reads
#: these files.
AN_ESCAPED_ACCESSOR_TERMINAL = tuple(
    _spelled_with_escapes(source) for source in (
        'var o = { ESCAPED[0067]et x(){ return 1; } }; console.log(o.x);',
        'var o = { ESCAPED[0073]et x(v){ this.q = v; } }; o.x = 1; console.log(o.q);',
        'class C { ESCAPED[0067]et x(){ return 1; } } console.log(new C().x);',
    )
)


AN_ESCAPED_STATIC_TERMINAL = tuple(
    _spelled_with_escapes(source) for source in (
        'class C { ESCAPED[0073]tatic m(){ return 1; } } console.log(C.m());',
        'class C { ESCAPED[0073]tatic { console.log(1); } } console.log(2);',
    )
)


AN_ESCAPED_ASYNC_TERMINAL = tuple(
    _spelled_with_escapes(source) for source in (
        'ESCAPED[0061]sync function f(){ return 1; } console.log(typeof f);',
    )
)


AN_ESCAPED_OF_TERMINAL = tuple(
    _spelled_with_escapes(source) for source in (
        'for (var x ESCAPED[006F]f [1]) { console.log(x); }',
        'for (const x ESCAPED[006F]f [1, 2]) { console.log(x); }',
    )
)


AN_ESCAPED_TARGET_TERMINAL = tuple(
    _spelled_with_escapes(source) for source in (
        'function f(){ return new.ESCAPED[0074]arget; } console.log(typeof f());',
    )
)


AN_ESCAPED_KEYWORD_OPERATOR = tuple(
    _spelled_with_escapes(source) for source in (
        'console.log([] ESCAPED[0069]nstanceof Array);',
        "console.log('a' ESCAPED[0069]n { a: 1 });",
        'console.log(ESCAPED[0074]ypeof 1);',
        'var o = { a: 1 }; console.log(ESCAPED[0064]elete o.a);',
        'console.log(ESCAPED[0076]oid 0);',
    )
)


A_NAME_WHOSE_CHARACTERS_SPELL_A_TERMINAL_WORD = _programs({
    'var lESCAPED[0065]t = [0]; lESCAPED[0065]t[0] = 5; console.log(lESCAPED[0065]t[0]);': '5\n',
    'var stESCAPED[0061]tic = [0]; static[0] = 5; console.log(static[0]);': '5\n',
    'var gESCAPED[0065]t = [0]; get[0] = 5; console.log(get[0]);': '5\n',
    'var asynESCAPED[0063] = [0]; async[0] = 5; console.log(async[0]);': '5\n',
    'var oESCAPED[0066] = [0]; of[0] = 5; console.log(of[0]);': '5\n',
    'var froESCAPED[006D] = [0]; from[0] = 5; console.log(from[0]);': '5\n',
    'var yielESCAPED[0064] = [0]; yield[0] = 5; console.log(yield[0]);': '5\n',
    'var awaiESCAPED[0074] = [0]; await[0] = 5; console.log(await[0]);': '5\n',
    'var targESCAPED[0065]t = [0]; target[0] = 5; console.log(target[0]);': '5\n',
})


THE_NAME_LET_READ_AT_THE_HEAD_OF_A_STATEMENT = tuple(
    _spelled_with_escapes(source) for source in (
        'var lESCAPED[0065]t = [0]; let[0] = 5; console.log(let[0]);',
    )
)


THE_SAME_FILE_WITH_NO_ESCAPE_AT_ALL = (
    'var let = [0]; let[0] = 5; console.log(let[0]);',
)


A_PARAMETER_NAMED_EVAL_OR_ARGUMENTS_WITH_AN_ESCAPE = tuple(map(_spelled_with_escapes, (
    "'use strict'; function f(evESCAPED[0061]l){ return 1; } console.log(typeof f);",
    "'use strict'; function f(argumentESCAPED[0073]){ return 1; } console.log(typeof f);",
    "'use strict'; var q = function (evESCAPED[0061]l){ return 1; }; console.log(typeof q);",
    "'use strict'; var q = function (argumentESCAPED[0073]){ return 1; }; console.log(typeof q);",
    "'use strict'; var q = { set p(evESCAPED[0061]l){} }; console.log(typeof q);",
    "'use strict'; var q = { set p(argumentESCAPED[0073]){} }; console.log(typeof q);",
    'class C { m(evESCAPED[0061]l){} } console.log(typeof C);',
    'class C { m(argumentESCAPED[0073]){} } console.log(typeof C);',
)))


THE_SAME_PARAMETER_WRITTEN_OUT = (
    "'use strict'; function f(eval){ return 1; } console.log(typeof f);",
    "'use strict'; function f(arguments){ return 1; } console.log(typeof f);",
    "'use strict'; var q = function (eval){ return 1; }; console.log(typeof q);",
    "'use strict'; var q = function (arguments){ return 1; }; console.log(typeof q);",
    "'use strict'; var q = { set p(eval){} }; console.log(typeof q);",
    "'use strict'; var q = { set p(arguments){} }; console.log(typeof q);",
    'class C { m(eval){} } console.log(typeof C);',
    'class C { m(arguments){} } console.log(typeof C);',
)


A_NAME_WRITTEN_WITH_AN_ESCAPE_AND_THE_TEXT_IT_COMES_BACK_AS = {
    _spelled_with_escapes(source): expected
    for source, expected in {
        'var ESCAPED[0061]bc = 1;': 'var abc = 1;',
        'console.log(o.ESCAPED[0061]bc);': 'console.log(o.abc);',
        'class ESCAPED[0043]ls {}': 'class Cls {}',
        "'use strict'; function f(evESCAPED[0061]l){ return 1; }":
            _spelled_with_escapes(
                "'use strict';\nfunction f(evESCAPED[0061]l) {\n  return 1;\n}"),
        "'use strict'; function f(argumentESCAPED[0073]){ return 1; }":
            _spelled_with_escapes(
                "'use strict';\nfunction f(argumentESCAPED[0073]) {\n  return 1;\n}"),
    }.items()
}


A_STORE_TO_LET_AND_THE_TEXTS_IT_MAY_COME_BACK_AS = {
    _spelled_with_escapes('lESCAPED[0065]t[0] = 5;'): (
        _spelled_with_escapes('(lESCAPED[0065]t[0] = 5);'),
        '(let[0] = 5);',
    ),
}


A_PROGRAM_WITH_NO_ESCAPE_ANYWHERE = {
    'var abc = 7; console.log(abc);': '7\n',
    'function f(prm){ return prm; } console.log(f(7));': '7\n',
    "console.log(Object.keys({ a: 1, b: 2 }).join('|'));": 'a|b\n',
    'class C { #prv = 7; read(){ return this.#prv; } } console.log(new C().read());': '7\n',
    'lbl: for (var i = 0; i < 3; i++) { if (i) break lbl; console.log(i); }': '0\n',
    'var let = [0]; console.log(let[0]);': '0\n',
}


A_STRING_SPELLED_WITH_AN_ESCAPE = _programs({
    "function f(){ 'use stricESCAPED[0074]'; return this === globalThis; } console.log(f());":
        'true\n',
    "console.log('aESCAPED[0062]c'.length);": '3\n',
})


A_PROLOGUE_STRING_WRITTEN_OUT = {
    "function f(){ 'use strict'; return this === globalThis; } console.log(f());": 'false\n',
}


A_PROGRAM_THE_TOOL_ONLY_MOVES = tuple(
    _spelled_with_escapes(source) for source in (
        'var lESCAPED[0065]t = [0]; lESCAPED[0065]t[0] = 5; console.log(lESCAPED[0065]t[0]);',
        "function f(x){ 'use stricESCAPED[0074]'; if (x) { return this === globalThis; } }"
        ' console.log(f(1));',
    )
)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestABindingWrittenWithAnEscapeIsTheNameThatEscapeDenotes(TestBase):

    def test_a_binding_and_a_read_spelled_differently_are_one_name(self):
        rows = A_BINDING_AND_A_READ_SPELLED_DIFFERENTLY
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAPropertyNameWrittenWithAnEscapeIsTheNameThatEscapeDenotes(TestBase):

    def test_a_key_and_a_read_spelled_differently_are_one_name(self):
        rows = A_PROPERTY_NAME_SPELLED_WITH_AN_ESCAPE
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAClassMemberNameWrittenWithAnEscapeIsTheNameThatEscapeDenotes(TestBase):

    def test_a_class_member_and_its_use_spelled_differently_are_one_name(self):
        rows = A_CLASS_MEMBER_NAME_SPELLED_WITH_AN_ESCAPE
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestALabelWrittenWithAnEscapeIsTheNameThatEscapeDenotes(TestBase):

    def test_a_label_and_the_jump_to_it_spelled_differently_are_one_label(self):
        rows = A_LABEL_SPELLED_WITH_AN_ESCAPE
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnEscapedSpellingOfEvalIsStillADirectEval(TestBase):

    def test_an_escaped_eval_sees_the_locals_of_its_caller(self):
        rows = AN_ESCAPED_EVAL_RUNNING_IN_ITS_CALLERS_SCOPE
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_an_eval_reached_indirectly_sees_no_local_however_it_is_spelled(self):
        rows = AN_EVAL_REACHED_INDIRECTLY_SEEING_NO_LOCAL
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnEscapedSpellingOfAnIntrinsicIsThatIntrinsic(TestBase):

    def test_an_intrinsic_named_with_an_escape_behaves_as_that_intrinsic(self):
        rows = AN_INTRINSIC_NAMED_WITH_AN_ESCAPE
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_an_escaped_name_a_local_shadows_reads_the_local(self):
        rows = AN_INTRINSIC_NAME_A_LOCAL_SHADOWS
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAKeyReadsBackAsTheCodeUnitsItIsSpelledIn(TestBase):

    def test_the_three_spellings_of_an_astral_key_read_the_same_code_units(self):
        rows = {
            _reading_back_the_units_of(key): '2 55349 56421\n'
            for key in AN_ASTRAL_KEY_SPELLED_THREE_WAYS
        }
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


class TestTheThreeSpellingsOfAnAstralKeyFoldToOneText(TestBase):

    def test_the_three_spellings_of_an_astral_key_fold_to_the_same_text(self):
        self.assertEqual(
            [folded(_reading_back_the_units_of(key)) for key in AN_ASTRAL_KEY_SPELLED_THREE_WAYS],
            ['console.log(2, 55349, 56421);'] * 3,
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnAstralCharacterIsANameOnlyWhereItIsWrittenWhole(TestBase):

    def test_a_program_naming_with_an_astral_character_still_prints_what_it_printed(self):
        rows = A_NAME_WRITTEN_WITH_AN_ASTRAL_CHARACTER
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_name_written_with_the_braced_escape_is_the_same_name(self):
        rows = A_NAME_WRITTEN_WITH_THE_BRACED_ESCAPE
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_two_surrogate_halves_written_separately_name_nothing(self):
        rows = THE_TWO_HALVES_OF_AN_ASTRAL_CHARACTER_WRITTEN_SEPARATELY
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            _refused(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAProgramNodeRefusesIsNotAnsweredWithOneThatRuns(TestBase):

    def test_an_escaped_reserved_word_is_no_variable(self):
        rows = AN_ESCAPED_RESERVED_WORD_WHERE_A_VARIABLE_WAS_EXPECTED
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual({source: before_and_after(source) for source in rows}, _refused(rows))

    def test_an_escape_naming_no_identifier_character_is_no_name(self):
        rows = AN_ESCAPE_NAMING_NO_IDENTIFIER_CHARACTER
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual({source: before_and_after(source) for source in rows}, _refused(rows))

    def test_an_escape_naming_no_code_point_is_no_name(self):
        rows = AN_ESCAPE_NAMING_NO_CODE_POINT
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual({source: before_and_after(source) for source in rows}, _refused(rows))

    def test_an_escaped_of_terminal_heads_no_for_of(self):
        rows = AN_ESCAPED_OF_TERMINAL
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual({source: before_and_after(source) for source in rows}, _refused(rows))

    def test_an_escaped_target_follows_no_new_dot(self):
        rows = AN_ESCAPED_TARGET_TERMINAL
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual({source: before_and_after(source) for source in rows}, _refused(rows))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestANameSpellingATerminalWordKeepsTheSpellingThatRuns(TestBase):

    def test_a_name_whose_characters_spell_a_terminal_word_still_runs(self):
        rows = A_NAME_WHOSE_CHARACTERS_SPELL_A_TERMINAL_WORD
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_the_same_name_read_at_the_head_of_a_statement_is_no_program(self):
        """
        A statement that begins with `let [` is a lexical declaration, never an expression, and
        `[0]` binds no name, so Node refuses both files although `let` is a variable here.
        """
        escaped = THE_NAME_LET_READ_AT_THE_HEAD_OF_A_STATEMENT
        self.assertEqual(_unspelled(escaped), [])
        rows = (*escaped, *THE_SAME_FILE_WITH_NO_ESCAPE_AT_ALL)
        self.assertEqual({source: before_and_after(source) for source in rows}, _refused(rows))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAParameterNamedEvalOrArgumentsKeepsTheSpellingThatRuns(TestBase):
    """
    Strict code may not bind a parameter named `eval` or `arguments`. Node 24 checks that over the
    characters typed rather than over the name they denote, so it accepts the escaped spelling and
    refuses the plain one; Node 26 refuses both. A class body is strict code without a directive.
    """

    def test_a_parameter_named_by_an_escape_behaves_after_the_deobfuscation_as_before(self):
        rows = A_PARAMETER_NAMED_EVAL_OR_ARGUMENTS_WITH_AN_ESCAPE
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual(
            {source: deobfuscated_behavior(source) for source in rows},
            {source: behavior(source) for source in rows},
        )

    def test_the_same_parameter_written_out_is_no_program(self):
        rows = THE_SAME_PARAMETER_WRITTEN_OUT
        self.assertEqual({source: before_and_after(source) for source in rows}, _refused(rows))


class TestAnEscapeIsSpentWhereThePlainSpellingIsTheSameProgram(TestBase):

    def test_a_name_comes_back_written_plainly_wherever_that_is_the_same_program(self):
        rows = A_NAME_WRITTEN_WITH_AN_ESCAPE_AND_THE_TEXT_IT_COMES_BACK_AS
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual({source: printed(source) for source in rows}, rows)

    def test_a_store_to_let_comes_back_bracketed_with_or_without_its_escape(self):
        rows = A_STORE_TO_LET_AND_THE_TEXTS_IT_MAY_COME_BACK_AS
        self.assertEqual(_unspelled(rows), [])
        for source, texts in rows.items():
            with self.subTest(source=source):
                self.assertIn(printed(source), texts)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAProgramWithNothingToRespellIsLeftAlone(TestBase):

    def test_an_equivalent_program_with_no_escape_prints_the_same(self):
        rows = A_PROGRAM_WITH_NO_ESCAPE_ANYWHERE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_prologue_string_spelled_with_an_escape_is_a_string_and_not_a_directive(self):
        rows = A_STRING_SPELLED_WITH_AN_ESCAPE
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_the_same_prologue_string_written_out_is_a_directive(self):
        rows = A_PROLOGUE_STRING_WRITTEN_OUT
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


class TestAProgramTheToolOnlyMovesComesBackAsItWent(TestBase):

    def test_a_program_the_tool_only_moves_comes_back_as_the_same_program(self):
        """
        Spelling either escape out would change the program: a statement headed by a plain
        `let[0] = 5` is a declaration, and a plainly typed `'use strict'` is a directive.
        """
        rows = A_PROGRAM_THE_TOOL_ONLY_MOVES
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual(
            [printed(deobfuscate_source(source)) for source in rows],
            [printed(source) for source in rows],
        )
