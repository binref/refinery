"""
The name an identifier carries is what its escapes denote, not the characters it was typed with.

An identifier may be written with unicode escapes, and two spellings that resolve to the same code
points are one name wherever a name is what the position holds: a variable, a function or class
name, a parameter, a catch parameter, a label, a property key, a member read, a shorthand property,
a class field or method, and a private name. A name denoting a built-in is no exception, so an
escaped spelling of `eval` is a direct eval and escaped spellings of `Object`, `Function` and
`globalThis` are those intrinsics.

Three things bound that. A character above the basic plane is named only by the braced escape form
or written out whole; its two surrogate halves written as separate four-digit escapes are not a
name. An escape naming something that is no identifier character at that position, or no code point
at all, is not a name either. And a grammar terminal cannot be spelled with an escape: where the
language reads for a terminal word, an escaped spelling of that word does not match it, while a name
whose escapes spell such a word is still a perfectly good name in every position that holds one.

A fourth is about where a name may stand rather than about what it is. `eval` and `arguments` are
the two names strict code refuses to bind in a parameter list, and Node decides that over the
characters typed: the escaped spelling binds what the plain one may not, and the file holding it is
one the engine reads.

Every case here is decided by Node, which is asked what the program does before the tool is asked to
agree. The hazard the module is written against is its own: a unicode escape typed into a Python
string is resolved by Python and reaches JavaScript as the character it names, so every escape here
is assembled from `chr(92)` and every table is checked for the backslash it must carry.

SECURITY: every program below is written out by this module and Node runs only those. Nothing from
`samples` may ever be handed to the engine.
"""
from __future__ import annotations

import re
import unittest

from collections.abc import Iterable

from test import TestBase
from test.lib.scripts.js.analysis.differential import deobfuscate_source, node_executable
from test.lib.scripts.js.ledger import (
    before_and_after,
    each_program_still_prints,
    folded,
    printed,
    returned_from_a_body,
)


_A_SPELLING = re.compile(r'(ESCAPED|LITERAL)\[([0-9A-F]+)\]')

_Behavior = tuple[str, str | None]


def _an_escape(code: int) -> str:
    """
    The JavaScript unicode escape naming the code point *code*, four-digit below the end of the
    basic plane and braced above it, the braced form being the only one that names such a character.

    The backslash is assembled from `chr(92)` and never written into this file. An escape written
    out here is one flattening of the source away from being the character it denotes, and a case
    that no longer holds the spelling it asks about asks nothing at all.
    """
    if code > 0xFFFF:
        return F'{chr(92)}u{{{code:X}}}'
    return F'{chr(92)}u{code:04X}'


def _spelled_with_escapes(source: str) -> str:
    """
    *source* with every `ESCAPED[XXXX]` replaced by the unicode escape naming that code point and
    every `LITERAL[XXXX]` by the character itself.
    """
    def spelling(match: re.Match[str]) -> str:
        code = int(match.group(2), 16)
        return _an_escape(code) if match.group(1) == 'ESCAPED' else chr(code)
    return _A_SPELLING.sub(spelling, source)


def _programs(rows: dict[str, str]) -> dict[str, str]:
    """
    *rows* with every source spelled out, mapping each program to what Node prints for it.
    """
    return {_spelled_with_escapes(source): prints for source, prints in rows.items()}


def _refused(sources: Iterable[str]) -> dict[str, tuple[_Behavior, _Behavior]]:
    """
    The pair `before_and_after` has to give for a program no engine reads: nothing printed and a
    `SyntaxError`, from the source and from whatever the tool writes for it alike.
    """
    return {source: (('', 'SyntaxError'), ('', 'SyntaxError')) for source in sources}


def _unspelled(sources: Iterable[str]) -> list[str]:
    """
    The sources among *sources* holding no backslash, which is the whole of what tells a case
    written with a JavaScript escape from one Python resolved into the character before Node saw it.
    """
    return [source for source in sources if chr(92) not in source]


#: A program that writes a name one way and reads it the other, mapped to what Node prints for it.
#: Both directions are here for every kind of binding the language has, so that a fix reaching only
#: the declaration side or only the read side is caught.
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


#: A program naming a property one way and reaching it the other, mapped to what Node prints for it.
#: The first four are the entry this replaces, which pinned the key, the read of a key an escape
#: wrote, the escaped read of a key written plainly, and a membership test over an escaped key.
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


#: A program naming a class member one way and reaching it the other, mapped to what Node prints for
#: it. A private name is the sharpest of these, since no expression outside the class body can reach
#: one and the two mentions have to be matched to each other and to nothing else.
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


#: A program labelling a statement one way and jumping to it the other, mapped to what Node prints
#: for it. The two rows that escape only one of the two mentions are what makes the pair a name
#: rather than a repeated spelling.
A_LABEL_SPELLED_WITH_AN_ESCAPE = _programs({
    'ESCAPED[006C]bl: for (var i = 0; i < 3; i++) '
    '{ if (i) break ESCAPED[006C]bl; console.log(i); }': '0\n',
    'ESCAPED[006C]bl: for (var i = 0; i < 3; i++) { if (i) break lbl; console.log(i); }': '0\n',
    'lbl: for (var i = 0; i < 3; i++) { if (i) break ESCAPED[006C]bl; console.log(i); }': '0\n',
    'outer: for (var i = 0; i < 2; i++) { for (var j = 0; j < 2; j++) '
    "{ continue ESCAPED[006F]uter; } } console.log('done');": 'done\n',
    'lbl: { console.log(1); break ESCAPED[006C]bl; } console.log(2);': '1\n2\n',
})


#: A program calling `eval` under an escaped spelling from inside a function that has a local,
#: mapped to what Node prints for it. A direct eval runs in its caller's scope, so the local is what
#: it reads, what it writes, and what shadows the built-in when the caller declared one.
AN_ESCAPED_EVAL_RUNNING_IN_ITS_CALLERS_SCOPE = _programs({
    "function f(){ var loc = 7; return ESCAPED[0065]val('loc'); } console.log(f());": '7\n',
    "function f(){ var loc = 1; ESCAPED[0065]val('loc = 9'); return loc; } console.log(f());":
        '9\n',
    "function f(){ ESCAPED[0065]val('var z = 3;'); return z; } console.log(f());": '3\n',
    "function f(){ var eval = function(){ return 'own'; }; return ESCAPED[0065]val('1'); } "
    'console.log(f());': 'own\n',
})


#: A program reaching `eval` through an expression rather than by name, mapped to what Node prints
#: for it. Such a call is an indirect eval whatever the name in it is spelled like: it runs in the
#: global scope, where the caller's local is not a binding at all.
AN_EVAL_REACHED_INDIRECTLY_SEEING_NO_LOCAL = _programs({
    "function f(){ var loc = 7; try { return (0, ESCAPED[0065]val)('loc'); } "
    'catch (e) { return e.constructor.name; } } console.log(f());': 'ReferenceError\n',
    "function f(){ var loc = 7; try { return (0, eval)('loc'); } "
    'catch (e) { return e.constructor.name; } } console.log(f());': 'ReferenceError\n',
})


#: A program naming an intrinsic with an escape, mapped to what Node prints for it. The name is the
#: whole of what makes each of these the built-in it reaches, so an escape that failed to denote it
#: would leave a name nothing in the program declares.
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


#: A program that declares a local under an intrinsic's name and then reads that name with an
#: escape, mapped to what Node prints for it. The escaped spelling is the same name, so the local is
#: what it finds and the intrinsic is not reached at all.
AN_INTRINSIC_NAME_A_LOCAL_SHADOWS = _programs({
    "function f(){ var Object = { keys: function(){ return ['z']; } }; "
    'return ESCAPED[004F]bject.keys({ a: 1 })[0]; } console.log(f());': 'z\n',
})


#: A key holding one character above the basic plane, spelled three ways: written out, written as a
#: string literal, and named by the braced escape. A property key read back is a string of UTF-16
#: code units, so all three answer the same length and the same two units.
AN_ASTRAL_KEY_SPELLED_THREE_WAYS = (
    _spelled_with_escapes('Object.keys({ LITERAL[1D465]: 1 })[0]'),
    _spelled_with_escapes("Object.keys({ 'LITERAL[1D465]': 1 })[0]"),
    _spelled_with_escapes('Object.keys({ ESCAPED[1D465]: 1 })[0]'),
)


def _reading_back_the_units_of(key: str) -> str:
    """
    A program printing the length of *key* and its first two UTF-16 code units.
    """
    return F'var k = {key}; console.log(k.length, k.charCodeAt(0), k.charCodeAt(1));'


#: A program naming a variable, a parameter, a member and a label with a character above the basic
#: plane written out, mapped to what Node prints for it. The name survives into the output in each,
#: since a name a fold takes away is a name whose spelling is never written back out.
A_NAME_WRITTEN_WITH_AN_ASTRAL_CHARACTER = _programs({
    'var LITERAL[1D465] = [0]; LITERAL[1D465][0] = 5; console.log(LITERAL[1D465][0]);': '5\n',
    'function f(LITERAL[1D465]){ return LITERAL[1D465] + globalThis.zz; } console.log(f(1));':
        'NaN\n',
    'console.log(globalThis.LITERAL[1D465]);': 'undefined\n',
    'LITERAL[1D465]: for (;;) { break LITERAL[1D465]; } console.log(1);': '1\n',
})


#: The same array under the same name, with the braced escape naming the character in at least one
#: of the three mentions, mapped to what Node prints for it. Two of the three mix the spellings
#: within one program, which is what makes them one name rather than two that happen to agree.
A_NAME_WRITTEN_WITH_THE_BRACED_ESCAPE = _programs({
    'var ESCAPED[1D465] = [0]; ESCAPED[1D465][0] = 5; console.log(ESCAPED[1D465][0]);': '5\n',
    'var LITERAL[1D465] = [0]; ESCAPED[1D465][0] = 5; console.log(LITERAL[1D465][0]);': '5\n',
    'var ESCAPED[1D465] = [0]; LITERAL[1D465][0] = 5; console.log(ESCAPED[1D465][0]);': '5\n',
})


#: A program spelling the two surrogate halves of one astral character as separate four-digit
#: escapes. Neither half is an identifier character on its own, so neither program is a program.
THE_TWO_HALVES_OF_AN_ASTRAL_CHARACTER_WRITTEN_SEPARATELY = tuple(
    _spelled_with_escapes(source) for source in (
        'var ESCAPED[D835]ESCAPED[DC65] = [0]; console.log(1);',
        'var LITERAL[1D465] = [0]; console.log(ESCAPED[D835]ESCAPED[DC65][0]);',
    )
)


#: A program binding a variable to a name whose escapes resolve to a reserved word. Such a name may
#: name a property but never a variable, so none of these is a file any engine reads.
AN_ESCAPED_RESERVED_WORD_WHERE_A_VARIABLE_WAS_EXPECTED = tuple(
    _spelled_with_escapes(source) for source in (
        'var ESCAPED[0069]f = 1; console.log(2);',
        'var ESCAPED[0074]his = 1; console.log(2);',
        'console.log(ESCAPED[0074]his);',
        'class C { m(){ return ESCAPED[0073]uper.toString; } } console.log(1);',
    )
)


#: A program whose escape names a character no identifier may hold at that position: a space, a
#: digit where a name begins, and a plus sign.
AN_ESCAPE_NAMING_NO_IDENTIFIER_CHARACTER = tuple(
    _spelled_with_escapes(source) for source in (
        'var aESCAPED[0020]b = 1; console.log(1);',
        'var ESCAPED[0031]a = 1; console.log(1);',
        'var aESCAPED[002B]b = 1; console.log(1);',
    )
)


#: A program whose escape names no code point at all: one past the largest there is, one with too
#: few digits, one with digits that are not hexadecimal, and one whose brace is never closed.
AN_ESCAPE_NAMING_NO_CODE_POINT = tuple(
    _spelled_with_escapes(source) for source in (
        'var aESCAPED[110000] = 1; console.log(1);',
        F'var a{chr(92)}u00 = 1; console.log(1);',
        F'var a{chr(92)}uZZZZ = 1; console.log(1);',
        F'var a{chr(92)}u{{61 = 1; console.log(1);',
    )
)


#: A program spelling `get` or `set` with an escape where an accessor's name follows it. The
#: language reads a terminal word there, and a terminal word is matched by the characters typed.
#: The law over this table is not stated here: the tool answers these files with programs that
#: run, and `test.lib.scripts.js.test_unfixed_defects` pins that.
AN_ESCAPED_ACCESSOR_TERMINAL = tuple(
    _spelled_with_escapes(source) for source in (
        'var o = { ESCAPED[0067]et x(){ return 1; } }; console.log(o.x);',
        'var o = { ESCAPED[0073]et x(v){ this.q = v; } }; o.x = 1; console.log(o.q);',
        'class C { ESCAPED[0067]et x(){ return 1; } } console.log(new C().x);',
    )
)


#: A program spelling `static` with an escape where a class member follows it, in both the member
#: and the initialization-block form.
#: The law over this table is not stated here: the tool answers these files with programs that
#: run, and `test.lib.scripts.js.test_unfixed_defects` pins that.
AN_ESCAPED_STATIC_TERMINAL = tuple(
    _spelled_with_escapes(source) for source in (
        'class C { ESCAPED[0073]tatic m(){ return 1; } } console.log(C.m());',
        'class C { ESCAPED[0073]tatic { console.log(1); } } console.log(2);',
    )
)


#: A program spelling `async` with an escape before the `function` it modifies.
#: The law over this table is not stated here: the tool answers these files with programs that
#: run, and `test.lib.scripts.js.test_unfixed_defects` pins that.
AN_ESCAPED_ASYNC_TERMINAL = tuple(
    _spelled_with_escapes(source) for source in (
        'ESCAPED[0061]sync function f(){ return 1; } console.log(typeof f);',
    )
)


#: A program spelling `of` with an escape in the head of a for-of.
AN_ESCAPED_OF_TERMINAL = tuple(
    _spelled_with_escapes(source) for source in (
        'for (var x ESCAPED[006F]f [1]) { console.log(x); }',
        'for (const x ESCAPED[006F]f [1, 2]) { console.log(x); }',
    )
)


#: A program spelling `target` with an escape after `new.`.
AN_ESCAPED_TARGET_TERMINAL = tuple(
    _spelled_with_escapes(source) for source in (
        'function f(){ return new.ESCAPED[0074]arget; } console.log(typeof f());',
    )
)


#: A program spelling a keyword operator with an escape. Each is a terminal word of the grammar
#: exactly as `if` and `else` are, so an escaped spelling of one is not that operator and the
#: program holding it is not a program.
#: The law over this table is not stated here: the tool answers these files with programs that
#: run, and `test.lib.scripts.js.test_unfixed_defects` pins that.
AN_ESCAPED_KEYWORD_OPERATOR = tuple(
    _spelled_with_escapes(source) for source in (
        'console.log([] ESCAPED[0069]nstanceof Array);',
        "console.log('a' ESCAPED[0069]n { a: 1 });",
        'console.log(ESCAPED[0074]ypeof 1);',
        'var o = { a: 1 }; console.log(ESCAPED[0064]elete o.a);',
        'console.log(ESCAPED[0076]oid 0);',
    )
)


#: A program binding a name whose escapes spell a word the grammar reads as a terminal somewhere
#: else, mapped to what Node prints for it. Each name is written once with an escape and read once
#: without, so the program says the two are one name; each is also a name no position here reads as
#: a terminal, so the program runs.
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


#: The same array under the same name, with the store written at the head of a statement and the
#: name there typed plainly. A lexical declaration is what the language reads at that position the
#: moment the escape is gone, and its binding list may not be an array literal.
THE_NAME_LET_READ_AT_THE_HEAD_OF_A_STATEMENT = tuple(
    _spelled_with_escapes(source) for source in (
        'var lESCAPED[0065]t = [0]; let[0] = 5; console.log(let[0]);',
    )
)


#: The same file with no escape anywhere in it, which the language refuses for the same reason.
THE_SAME_FILE_WITH_NO_ESCAPE_AT_ALL = (
    'var let = [0]; let[0] = 5; console.log(let[0]);',
)


#: A program binding a parameter named `eval` or `arguments` with one character written as an
#: escape, mapped to what Node prints for it. Every one of them is a file the engine reads and every
#: one of them binds a name the same file could not bind written out, in each of the four places a
#: parameter list stands: a function declaration, a function expression, a setter, and a class
#: method whose body is strict with no directive saying so.
A_PARAMETER_NAMED_EVAL_OR_ARGUMENTS_WITH_AN_ESCAPE = _programs({
    "'use strict'; function f(evESCAPED[0061]l){ return 1; } console.log(typeof f);":
        'function\n',
    "'use strict'; function f(argumentESCAPED[0073]){ return 1; } console.log(typeof f);":
        'function\n',
    "'use strict'; var q = function (evESCAPED[0061]l){ return 1; }; console.log(typeof q);":
        'function\n',
    "'use strict'; var q = function (argumentESCAPED[0073]){ return 1; }; console.log(typeof q);":
        'function\n',
    "'use strict'; var q = { set p(evESCAPED[0061]l){} }; console.log(typeof q);": 'object\n',
    "'use strict'; var q = { set p(argumentESCAPED[0073]){} }; console.log(typeof q);": 'object\n',
    'class C { m(evESCAPED[0061]l){} } console.log(typeof C);': 'function\n',
    'class C { m(argumentESCAPED[0073]){} } console.log(typeof C);': 'function\n',
})


#: The same eight programs with the escape written out, which is the one difference between them and
#: the eight above.
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


#: A program written with an escape, mapped to the text the tool writes for it with no pass run over
#: it. The first three name something an escape is the only unusual thing about, and the plain
#: spelling of each is the same program, so the escape is spent rather than kept. The last three are
#: the names for which it is not: two a rule is stated over the text of, and one a production
#: matches as a terminal.
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
        'var lESCAPED[0065]t = 1;': _spelled_with_escapes('var lESCAPED[0065]t = 1;'),
    }.items()
}


#: A program with no escape anywhere, mapped to what Node prints for it. Each is the twin of a
#: program above and says what that program says without asking anything about a spelling, so a
#: change that moved one of these would be a change to something else entirely.
A_PROGRAM_WITH_NO_ESCAPE_ANYWHERE = {
    'var abc = 7; console.log(abc);': '7\n',
    'function f(prm){ return prm; } console.log(f(7));': '7\n',
    "console.log(Object.keys({ a: 1, b: 2 }).join('|'));": 'a|b\n',
    'class C { #prv = 7; read(){ return this.#prv; } } console.log(new C().read());': '7\n',
    'lbl: for (var i = 0; i < 3; i++) { if (i) break lbl; console.log(i); }': '0\n',
    'var let = [0]; console.log(let[0]);': '0\n',
}


#: A prologue string written with an escape, mapped to what Node prints for it. A directive is
#: recognized by the characters typed, so this string is an ordinary one and the function holding it
#: stays sloppy. The second row is a string an escape shortens by two characters, which is what a
#: string escape always is: part of a value and never part of a name.
A_STRING_SPELLED_WITH_AN_ESCAPE = _programs({
    "function f(){ 'use stricESCAPED[0074]'; return this === globalThis; } console.log(f());":
        'true\n',
    "console.log('aESCAPED[0062]c'.length);": '3\n',
})


#: The same prologue string written out, mapped to what Node prints for it. This one is a directive,
#: which makes the function strict and leaves `this` undefined where the escaped spelling leaves the
#: global object.
A_PROLOGUE_STRING_WRITTEN_OUT = {
    "function f(){ 'use strict'; return this === globalThis; } console.log(f());": 'false\n',
}


#: A program whose every name is spelled with an escape that the tool has nothing to reduce in.
#: Each is a file that has to come back as the file it went in as, and what makes that a question
#: is that writing any of these names out plainly changes what the program does or whether it is
#: one at all. The escaped string stands ahead of a `return` no run is certain to reach, which is
#: the one shape that keeps it standing: it is no directive, so the function stays sloppy, and its
#: plain spelling is one.
A_PROGRAM_THE_TOOL_ONLY_MOVES = tuple(
    _spelled_with_escapes(source) for source in (
        'var lESCAPED[0065]t = [0]; lESCAPED[0065]t[0] = 5; console.log(lESCAPED[0065]t[0]);',
        "function f(x){ 'use stricESCAPED[0074]'; if (x) { return this === globalThis; } }"
        ' console.log(f(1));',
    )
)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestABindingWrittenWithAnEscapeIsTheNameThatEscapeDenotes(TestBase):
    """
    A binding and a read of it are one name when their escapes resolve alike, in both directions and
    for every kind of name the language binds. Where they are held apart, the declaration matches no
    read, reads as unused, and is dropped, and the file that comes back throws where the program it
    replaced printed a number.
    """

    def test_a_binding_and_a_read_spelled_differently_are_one_name(self):
        """
        Node prints `7` for sixteen of the seventeen programs of
        `A_BINDING_AND_A_READ_SPELLED_DIFFERENTLY` and `24` for the function expression that calls
        itself by its own name, the spelling with the escape standing on the declaration in half of
        them and on the read in the other half.
        """
        rows = A_BINDING_AND_A_READ_SPELLED_DIFFERENTLY
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAPropertyNameWrittenWithAnEscapeIsTheNameThatEscapeDenotes(TestBase):
    """
    A property key carries the name its escapes resolve to, and so does a member access, a shorthand
    property, a method name and a computed key built from a name. In a binding a mismatched spelling
    costs the declaration; in a property it costs an answer, since every one of these folds to a
    constant and a key held under the characters typed folds to the wrong one.
    """

    def test_a_key_and_a_read_spelled_differently_are_one_name(self):
        """
        Node prints `a|b`, `7`, `1`, `true`, `7`, `7`, `undefined`, `7`, `7`, `7`, `7` and `null`
        for the twelve programs of `A_PROPERTY_NAME_SPELLED_WITH_AN_ESCAPE`, which write and read a
        key through an object literal, a member access, a member write, `delete`, `Object.keys`, a
        membership test, a shorthand property, a method, an accessor, a computed key and the
        `__proto__` form that sets a prototype rather than a property.
        """
        rows = A_PROPERTY_NAME_SPELLED_WITH_AN_ESCAPE
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAClassMemberNameWrittenWithAnEscapeIsTheNameThatEscapeDenotes(TestBase):
    """
    A class field, a method, a static member, an accessor, the `constructor` a class body is
    recognized by, and a private name are all named by an identifier, and each of them carries the
    name its escapes denote.
    """

    def test_a_class_member_and_its_use_spelled_differently_are_one_name(self):
        """
        Node prints `7` for eight of the nine programs of
        `A_CLASS_MEMBER_NAME_SPELLED_WITH_AN_ESCAPE` and `true false` for the one asking whether a
        private name is in an object. A private name is the sharpest of these, since it is reachable
        from nowhere but the class body and the two mentions have to be matched to each other.
        """
        rows = A_CLASS_MEMBER_NAME_SPELLED_WITH_AN_ESCAPE
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestALabelWrittenWithAnEscapeIsTheNameThatEscapeDenotes(TestBase):
    """
    A label is a name too, and a jump reaches the label whose name matches its own. A label nothing
    jumps to and a jump to a label nothing declares are both refused by the language, so a spelling
    read as two names turns a file that runs into one no engine reads.
    """

    def test_a_label_and_the_jump_to_it_spelled_differently_are_one_label(self):
        """
        Node prints `0` for the three loop programs of `A_LABEL_SPELLED_WITH_AN_ESCAPE`, `done` for
        the one whose inner loop continues the outer, and `1` then `2` for the labelled block. Two
        of the five escape only one of the two mentions, which is where the two spellings have to be
        matched to each other rather than merely repeated.
        """
        rows = A_LABEL_SPELLED_WITH_AN_ESCAPE
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnEscapedSpellingOfEvalIsStillADirectEval(TestBase):
    """
    A call whose callee is the name `eval` is a direct eval and runs its argument in the scope of
    its caller. The name is the name its escapes denote, so an escaped spelling makes the call no
    less direct: the caller's local is what the code reads, what it writes, and what it declares
    into, and a local named `eval` is what the call reaches when the caller declared one.
    """

    def test_an_escaped_eval_sees_the_locals_of_its_caller(self):
        """
        Node prints `7`, `9`, `3` and `own` for the four programs of
        `AN_ESCAPED_EVAL_RUNNING_IN_ITS_CALLERS_SCOPE`, which read a local, write one, declare one
        the caller then returns, and call a local function the caller bound under the name `eval`.
        """
        rows = AN_ESCAPED_EVAL_RUNNING_IN_ITS_CALLERS_SCOPE
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_an_eval_reached_indirectly_sees_no_local_however_it_is_spelled(self):
        """
        The control for the test above. Node prints `ReferenceError` for both programs of
        `AN_EVAL_REACHED_INDIRECTLY_SEEING_NO_LOCAL`, which differ only in whether the name inside
        the sequence carries an escape: neither is a direct eval, so neither reads the local, and
        the escape is therefore not what decides the answer in the test above.
        """
        rows = AN_EVAL_REACHED_INDIRECTLY_SEEING_NO_LOCAL
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnEscapedSpellingOfAnIntrinsicIsThatIntrinsic(TestBase):
    """
    An intrinsic is reached by its name and by nothing else, so a spelling with an escape reaches it
    exactly as the plain spelling does — and a local declared under that name shadows both alike.
    """

    def test_an_intrinsic_named_with_an_escape_behaves_as_that_intrinsic(self):
        """
        Node prints `a,b`, `7`, `true`, `7`, the JSON text, `42`, `AB`, `true`, `true`, `0` and `7`
        for the eleven programs of `AN_INTRINSIC_NAMED_WITH_AN_ESCAPE`, which name `Object`,
        `Function`, `globalThis` twice, `JSON`, `parseInt`, `String`, `NaN`, `undefined`, `Infinity`
        and the `arguments` object a call supplies.
        """
        rows = AN_INTRINSIC_NAMED_WITH_AN_ESCAPE
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_an_escaped_name_a_local_shadows_reads_the_local(self):
        """
        Node prints `z` for the one program of `AN_INTRINSIC_NAME_A_LOCAL_SHADOWS`, whose function
        declares its own `Object` and then reads the name with an escape: the escaped spelling is
        the same name, so the local is what it finds and the built-in is never reached.
        """
        rows = AN_INTRINSIC_NAME_A_LOCAL_SHADOWS
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAKeyReadsBackAsTheCodeUnitsItIsSpelledIn(TestBase):
    """
    A property key read back is a JavaScript string, which is a sequence of UTF-16 code units. One
    character above the basic plane is two of them, and it is two of them however the key was
    named — by a bare identifier, by a string literal, or by the braced escape.
    """

    def test_the_three_spellings_of_an_astral_key_read_the_same_code_units(self):
        """
        Node prints `2 55349 56421` for all three programs, the two numbers being the high and low
        surrogate of the character the key holds.
        """
        rows = {
            _reading_back_the_units_of(key): '2 55349 56421\n'
            for key in AN_ASTRAL_KEY_SPELLED_THREE_WAYS
        }
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


class TestTheThreeSpellingsOfAnAstralKeyFoldToOneText(TestBase):
    """
    The tool's half of `TestAKeyReadsBackAsTheCodeUnitsItIsSpelledIn`, which needs no engine to ask:
    the three spellings are one key, so the three folds are one text.
    """

    def test_the_three_spellings_of_an_astral_key_fold_to_the_same_text(self):
        """
        Each of the three programs folds to one call, and the constants in it are the ones Node
        prints for the class above. A key held as one code point folds the identifier-named spelling
        to a different length and a different first unit than the string-literal spelling it is
        identical to.
        """
        self.assertEqual(
            [folded(_reading_back_the_units_of(key)) for key in AN_ASTRAL_KEY_SPELLED_THREE_WAYS],
            ['console.log(2, 55349, 56421);'] * 3,
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnAstralCharacterIsANameOnlyWhereItIsWrittenWhole(TestBase):
    """
    A character above the basic plane is named by writing it out or by the braced escape form, and
    those two spellings are one name. Its two surrogate halves written as separate four-digit
    escapes are not: neither half is an identifier character, so a file spelling a name that way is
    no program.

    A name is only spelled back out where it survives the reduction, so every program here keeps the
    name it declares.
    """

    def test_a_name_written_with_an_astral_character_is_spelled_back_as_that_character(self):
        """
        Node prints `5` for the program of `A_NAME_WRITTEN_WITH_AN_ASTRAL_CHARACTER` that stores
        into an array under the name, `NaN` for the one taking it as a parameter, `undefined` for
        the member read, and `1` for the labelled loop.
        """
        rows = A_NAME_WRITTEN_WITH_AN_ASTRAL_CHARACTER
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_name_written_with_the_braced_escape_is_the_same_name(self):
        """
        Node prints `5` for all three programs of `A_NAME_WRITTEN_WITH_THE_BRACED_ESCAPE`, two of
        which write the name one way and read it the other, which is what says that the braced
        escape and the character written out are one name.
        """
        rows = A_NAME_WRITTEN_WITH_THE_BRACED_ESCAPE
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_two_surrogate_halves_written_separately_name_nothing(self):
        """
        Node refuses both programs of `THE_TWO_HALVES_OF_AN_ASTRAL_CHARACTER_WRITTEN_SEPARATELY`
        with a `SyntaxError` and prints nothing, one spelling the halves in a declaration and the
        other in a read of a name declared with the character written out.
        """
        rows = THE_TWO_HALVES_OF_AN_ASTRAL_CHARACTER_WRITTEN_SEPARATELY
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            _refused(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAProgramNodeRefusesIsNotAnsweredWithOneThatRuns(TestBase):
    """
    Three things an escape cannot do bound the rule that a name is what its escapes denote: it
    cannot spell a reserved word where a variable is expected, it cannot name a character that is no
    identifier character or no code point at all, and it cannot match a terminal word of the
    grammar. A file doing any of them is refused by every engine, and the answer the tool gives for
    one has to be refused as well — a file that runs where the original never could is the one
    answer that tells an analyst something the program never did.
    """

    def test_an_escaped_reserved_word_is_no_variable(self):
        """
        Node refuses all four programs of `AN_ESCAPED_RESERVED_WORD_WHERE_A_VARIABLE_WAS_EXPECTED`
        with a `SyntaxError` and prints nothing: a name whose escapes resolve to `if`, `this` or
        `super` may name a property but never a binding or a reference.
        """
        rows = AN_ESCAPED_RESERVED_WORD_WHERE_A_VARIABLE_WAS_EXPECTED
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual({source: before_and_after(source) for source in rows}, _refused(rows))

    def test_an_escape_naming_no_identifier_character_is_no_name(self):
        """
        Node refuses all three programs of `AN_ESCAPE_NAMING_NO_IDENTIFIER_CHARACTER` with a
        `SyntaxError` and prints nothing, the escapes naming a space, a digit where a name begins,
        and a plus sign.
        """
        rows = AN_ESCAPE_NAMING_NO_IDENTIFIER_CHARACTER
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual({source: before_and_after(source) for source in rows}, _refused(rows))

    def test_an_escape_naming_no_code_point_is_no_name(self):
        """
        Node refuses all four programs of `AN_ESCAPE_NAMING_NO_CODE_POINT` with a `SyntaxError` and
        prints nothing: one names a value past the largest code point there is, and the other three
        are escapes the lexer cannot finish reading at all.
        """
        rows = AN_ESCAPE_NAMING_NO_CODE_POINT
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual({source: before_and_after(source) for source in rows}, _refused(rows))

    def test_an_escaped_of_terminal_heads_no_for_of(self):
        """
        Node refuses both programs of `AN_ESCAPED_OF_TERMINAL` with a `SyntaxError` and prints
        nothing, with `var` and with `const` in the head.
        """
        rows = AN_ESCAPED_OF_TERMINAL
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual({source: before_and_after(source) for source in rows}, _refused(rows))

    def test_an_escaped_target_follows_no_new_dot(self):
        """
        Node refuses the one program of `AN_ESCAPED_TARGET_TERMINAL` with a `SyntaxError` and prints
        nothing: `new.target` is one token sequence of the grammar and not a member access whose key
        may be spelled freely.
        """
        rows = AN_ESCAPED_TARGET_TERMINAL
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual({source: before_and_after(source) for source in rows}, _refused(rows))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestANameSpellingATerminalWordKeepsTheSpellingThatRuns(TestBase):
    """
    The other side of the terminal rule. A name whose escapes spell a terminal word is a name
    wherever the grammar is not reading for that word, and writing it out plainly is what turns it
    back into the word. `let` is the sharp case, because a lexical declaration is what the language
    reads at the head of a statement the moment the name is typed without an escape.
    """

    def test_a_name_whose_characters_spell_a_terminal_word_still_runs(self):
        """
        Node prints `5` for all nine programs of `A_NAME_WHOSE_CHARACTERS_SPELL_A_TERMINAL_WORD`,
        whose names spell `let`, `static`, `get`, `async`, `of`, `from`, `yield`, `await` and
        `target`. Each writes the name once with an escape and once without, so a file that came
        back with either spelling dropped would be a file about a different name.
        """
        rows = A_NAME_WHOSE_CHARACTERS_SPELL_A_TERMINAL_WORD
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_the_same_name_read_at_the_head_of_a_statement_is_no_program(self):
        """
        The control for the test above. Node refuses both files with a `SyntaxError` and prints
        nothing: the array is the same and the name is the same, and the one difference from the
        program that prints `5` is that a statement begins with `let` typed plainly, which the
        language reads as a declaration whose binding list would have to be an array literal.
        """
        escaped = THE_NAME_LET_READ_AT_THE_HEAD_OF_A_STATEMENT
        self.assertEqual(_unspelled(escaped), [])
        rows = (*escaped, *THE_SAME_FILE_WITH_NO_ESCAPE_AT_ALL)
        self.assertEqual({source: before_and_after(source) for source in rows}, _refused(rows))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAParameterNamedEvalOrArgumentsKeepsTheSpellingThatRuns(TestBase):
    """
    `eval` and `arguments` are the two names a parameter list may not bind in strict code, and the
    engine decides that over the characters typed rather than over the name they denote: the two
    programs differ in nothing but an escape, and the engine reads one of them and refuses the
    other. A name is what its escapes denote everywhere else in this module, and this is the one
    place where writing that name out is not the same file.
    """

    def test_a_parameter_named_by_an_escape_binds_what_the_plain_spelling_may_not(self):
        """
        Node prints `function` for six of the eight programs of
        `A_PARAMETER_NAMED_EVAL_OR_ARGUMENTS_WITH_AN_ESCAPE` and `object` for the two whose setter
        stands in an object literal, the parameter being named `eval` or `arguments` with one
        character written as an escape in a function declaration, a function expression, a setter
        and a class method.
        """
        rows = A_PARAMETER_NAMED_EVAL_OR_ARGUMENTS_WITH_AN_ESCAPE
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_the_same_parameter_written_out_is_no_program(self):
        """
        The control for the test above. Node refuses all eight programs of
        `THE_SAME_PARAMETER_WRITTEN_OUT` with a `SyntaxError` and prints nothing, the escape being
        the whole of what separates each from the program above that runs. The two class methods
        carry no directive, a class body being strict code without one.
        """
        rows = THE_SAME_PARAMETER_WRITTEN_OUT
        self.assertEqual({source: before_and_after(source) for source in rows}, _refused(rows))


class TestAnEscapeIsSpentWhereThePlainSpellingIsTheSameProgram(TestBase):
    """
    A name is written back out as itself, and the spelling it was typed with is kept only where that
    spelling is what says which reading the file meant. Two kinds of word are: one a production
    matches as a terminal, and one a rule is stated over the characters of.
    """

    def test_a_name_comes_back_written_plainly_wherever_that_is_the_same_program(self):
        """
        The six programs of `A_NAME_WRITTEN_WITH_AN_ESCAPE_AND_THE_TEXT_IT_COMES_BACK_AS`, spelled
        by the synthesizer with no pass run over them. The first three lose the escape, naming a
        variable, a member and a class; the two parameters and the array named `let` keep it, and
        the programs `TestAParameterNamedEvalOrArgumentsKeepsTheSpellingThatRuns` and
        `TestANameSpellingATerminalWordKeepsTheSpellingThatRuns` run are what say they must.
        """
        rows = A_NAME_WRITTEN_WITH_AN_ESCAPE_AND_THE_TEXT_IT_COMES_BACK_AS
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual({source: printed(source) for source in rows}, rows)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAProgramWithNothingToRespellIsLeftAlone(TestBase):
    """
    The controls the rest of the module rests on. A program with no escape in it must answer the
    same before and after, or a change reported above was a change to something else; and a string
    that merely looks like a directive is a string, the escape in it being part of a value rather
    than part of a name.
    """

    def test_an_equivalent_program_with_no_escape_prints_the_same(self):
        """
        Node prints `7`, `7`, `a|b`, `7`, `0` and `0` for the six programs of
        `A_PROGRAM_WITH_NO_ESCAPE_ANYWHERE`, each of them the plainly spelled twin of a program
        above.
        """
        rows = A_PROGRAM_WITH_NO_ESCAPE_ANYWHERE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_prologue_string_spelled_with_an_escape_is_a_string_and_not_a_directive(self):
        """
        Node prints `true` for the function whose prologue string spells `use strict` with an
        escape, and `3` for the program reading the length of a string an escape shortens by two
        characters.
        """
        rows = A_STRING_SPELLED_WITH_AN_ESCAPE
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_the_same_prologue_string_written_out_is_a_directive(self):
        """
        The control for the test above. Node prints `false` for the one program of
        `A_PROLOGUE_STRING_WRITTEN_OUT`, whose only difference from the escaped spelling is the two
        characters the escape stood for: it is a directive, the function is strict, and a strict
        function called with no receiver is called with `this` left undefined.
        """
        rows = A_PROLOGUE_STRING_WRITTEN_OUT
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


class TestAProgramTheToolOnlyMovesComesBackAsItWent(TestBase):
    """
    The tool's half of `TestAProgramWithNothingToRespellIsLeftAlone`, which needs no engine to ask.
    A file the tool has nothing to reduce in has to come back as the file it went in as, and what
    makes that a question is that writing either name out plainly changes what the program does or
    whether it is one at all.
    """

    def test_a_program_the_tool_only_moves_comes_back_as_the_same_program(self):
        """
        Both programs of `A_PROGRAM_THE_TOOL_ONLY_MOVES` come back spelled exactly as the parser
        read them, compared through the synthesizer so that layout is not what is being asserted.
        Writing either name out plainly would change the file: one is the array named `let` and the
        other is the string that is not a directive.
        """
        rows = A_PROGRAM_THE_TOOL_ONLY_MOVES
        self.assertEqual(_unspelled(rows), [])
        self.assertEqual(
            [printed(deobfuscate_source(source)) for source in rows],
            [printed(source) for source in rows],
        )
