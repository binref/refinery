"""
A call to a function that wraps what its body returns answers the wrapper, never the value.

`async function m() { return 7; }` called answers a promise; `function* g() { return 7; }` called
answers a generator object whose completion value is `7` and which yields nothing at all. Neither is
`7`. A pass that reads such a body and answers the call with what the body returned hands back a
program that computes something else, and hands it back looking clean: nothing throws where the
program is only read, nothing is half-rewritten, and the analyst gets no signal that the answer is
not the one the language gives.

Eleven sites across ten passes do it. Each has its own entry here, and each entry is asked three
ways:

- the shape the pass exists for, folded, so that a guard which refuses too much is caught by the
  control rather than by silence — killing `stringarray._match_wrapper` outright leaves the rest of
  the suite green, and a site witnessed by nothing is a site a guard can quietly empty;
- the same shape with the keyword, read for what still stands in the output, which needs no engine
  and so is the reading that survives on a machine with no Node.js;
- the same shape run in Node before and after, which is what says the two agree.

**The read has to be one the two answers disagree on.** `typeof decode(P).then` for a *generator*
answers `undefined` in Node and here alike, because a generator object has no `.then` either, and the
row is then blind to a fold that is wrong the whole time. `.then` for `async`, `.next` for a generator
and for an async generator.

The tally `_what_wraps_and_what_calls_it` reads is deliberately its own and does not ask
`refinery.lib.scripts.js.model`: a test that asks the library whether the library is right reports
only that it is self-consistent.

SECURITY: every program here is hand-authored in this file and benign, except the base91 table and
decoder, which are the fixture `test.lib.scripts.js.deobfuscation.test_b91strings` builds and which
are written out in full below so that what the engine is handed is what is read here. No sample and
no stored obfuscator fixture may be fed to this.
"""
from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import (
    deobfuscate_within,
    node_executable,
)
from test.lib.scripts.js.ledger import (
    before_and_after,
    each_program_still_prints,
    folded,
    well_formed,
)

from refinery.lib.scripts import Node
from refinery.lib.scripts.js.analysis.model import FUNCTION_NODES
from refinery.lib.scripts.js.model import (
    JsArrayPattern,
    JsAssignmentExpression,
    JsAssignmentPattern,
    JsCallExpression,
    JsCatchClause,
    JsClassDeclaration,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsFunctionNode,
    JsIdentifier,
    JsImportDefaultSpecifier,
    JsImportNamespaceSpecifier,
    JsImportSpecifier,
    JsMemberExpression,
    JsMethodDefinition,
    JsObjectPattern,
    JsProperty,
    JsRestElement,
    JsScript,
    JsStringLiteral,
    JsSwitchCase,
    JsVarKind,
    JsVariableDeclaration,
    JsVariableDeclarator,
    is_async_function,
    is_generator_function,
    wraps_return,
)
from refinery.lib.scripts.js.deobfuscation.interpreter import JsInterpreter
from refinery.lib.scripts.js.parser import JsParser

NL = chr(10)


def _lines(*parts: str) -> str:
    return NL.join(parts) + NL


def a_call_wrapper(kw: str = '', read: str = 'w(7)') -> str:
    return _lines(
        'function t(a) { return a; }',
        F'{kw}function w(a) {{ return t(a); }}',
        F'console.log({read});',
    )


def an_iife(read: str = '(function (a) { return a; })(7)') -> str:
    return _lines(F'console.log({read});')


def a_global_finder(
    kw: str = '', read: str = 'g() === globalThis', closure_head: str = 'function',
) -> str:
    """
    *closure_head* writes the keyword onto the closure the call reaches rather than onto the finder,
    which is where the finder's own effect summary cannot answer for it: `EffectSummary.absorb`
    leaves `wraps_return` out, so a callee's wrapping never reaches its caller's summary.
    """
    return _lines(
        F'{kw}function g() {{',
        F'  var a = [{closure_head} () {{ return globalThis; }}];',
        '  var r = a[0]();',
        '  return r;',
        '}',
        F'console.log({read});',
    )


def a_callback(read: str = '[1, 2].filter(function (x) { return x > 1; }).length') -> str:
    """
    A predicate handed to an array method, which the interpreter runs rather than reads. Every
    promise and every generator object is truthy, so a wrapping predicate keeps both elements.
    """
    return _lines(F'console.log({read});')


def a_callback_inside_a_body(kw: str = '') -> str:
    return _lines(
        'function f() {',
        F'  return [1, 2].filter({kw}function (x) {{ return x > 1; }}).length;',
        '}',
        'console.log(f());',
    )


def a_rotation(kw: str = '', read: str = 'x.join("")') -> str:
    """
    A rotation over a literal array of ten elements, which is the floor the pass recognizes one at.
    """
    return _lines(
        F'{kw}function rot(arr, n) {{',
        '  for (var i = 0; i < n; i++) arr.push(arr.shift());',
        '  return arr;',
        '}',
        'var x = rot(["b", "c", "d", "e", "f", "g", "h", "i", "j", "a"], 9);',
        F'console.log({read});',
    )


def a_string_array(accessor_kw: str = '', holder_kw: str = '', read: str = 'ACC(0)') -> str:
    """
    A holder that replaces itself on its first call, an accessor that reads it by index, and a
    rotation loop whose sum matches its target at once, so the strings stand as written.
    """
    return _lines(
        F"{holder_kw}function A() {{ var s = ['hello', 'world'];"
        ' A = function () { return s; }; return A(); }',
        F'{accessor_kw}function ACC(i, k) {{ i = i - 0; var a = A();'
        ' var r = a[i]; return r; }',
        '(function (getArray, target) {',
        '  var arr = getArray();',
        '  while (true) {',
        '    var sum = 1;',
        "    if (sum === target) break; else arr['push'](arr['shift']());",
        '  }',
        '})(A, 1);',
        F'console.log({read});',
    )


def a_string_array_whose_rotation_runs(
    holder_head: str = 'function',
    target: int = 3,
    replacement_head: str = 'function',
    rotation_head: str = 'function',
) -> str:
    """
    The same three parts written the way an obfuscator emits them: the checksum is read through the
    accessor, so it answers differently at each rotation, and a target the written order does not
    meet makes the loop turn the array over before it breaks.

    The loop is what reads what the holder answered. In `a_string_array` it breaks before it touches
    the array, which is why that program agrees with Node for an `async` holder and this one does
    not: here `arr` is the promise the holder answered, and a promise has no `shift`.

    Each of the three functions takes its whole head rather than a keyword written in front of one,
    because a generator is spelled `function*` and a prefix cannot produce that.

    *replacement_head* writes the head of the function the holder installs in its own place, which
    is the one every call after the first reaches. *rotation_head* writes the head of the loop's
    own function: calling a generator never runs its body, so a generator rotation turns the array
    over in the pass and not in the program.
    """
    return _lines(
        F"{holder_head} A() {{ var s = ['3', '5'];"
        F' A = {replacement_head} () {{ return s; }}; return A(); }}',
        'function ACC(i, k) { i = i - 0; var a = A();'
        ' var r = a[i]; return r; }',
        F'({rotation_head} (getArray, target) {{',
        '  var arr = getArray();',
        '  while (!![]) {',
        '    try {',
        '      var sum = parseInt(ACC(0)) / 1;',
        "      if (sum === target) break; else arr['push'](arr['shift']());",
        "    } catch (e) { arr['push'](arr['shift']()); }",
        '  }',
        F'}})(A, {target});',
        'console.log(ACC(0));',
    )


AN_ENCODED_STRING = 'hJQxp9Pvj3X2QId3C4RuMOe1C4EpuSg2b/8JyqzSWjrQm+VgNNg='


def a_scramble(kw: str = '', read: str = F"typeof decode('{AN_ENCODED_STRING}').then") -> str:
    """
    A Scramble cipher instance behind a decode wrapper. `pb` and `decrypt` are stubs so that the
    program runs at all; the read is of the value the pass substitutes and not of what they compute.
    """
    return _lines(
        "function pb() { return 'K'; }",
        "function decrypt() { return 'X'; }",
        'class Scramble {',
        '  constructor(pw, salt) {',
        "    this.masterKey = pb(pw, salt, 200000, 32, 'sha256');",
        '    this.rounds = 3;',
        '  }',
        '  decode(input) { return decrypt(input, this.masterKey, this.rounds); }',
        '}',
        "var key = '2aaa9053353088d4d49b5bf32f403f2d85b3df97c9a9beedfcdbb1ecc27ba9c6';",
        "var salt = 'fec5863b88643968ecff0c2c8afecbaf';",
        'var instance = new Scramble(key, salt);',
        F'{kw}function decode(x) {{ return instance.decode(x); }}',
        F'console.log({read});',
    )


A_BASE91_ALPHABET = (
    '0,Fz)`Q(lH=j5gK[i8~mJt_b&qr/fW^Y2]?#|@.!$cLZ9BN>A1o7ye+D%IM}O6;pV:P*E3CRnxXSh{wvaTUuk4G'
    + chr(92) + '"s<d'
)


def a_base91_table(
    decoder_kw: str = '',
    accessor_kw: str = '',
    read: str = "typeof accessor(12).then",
) -> str:
    """
    The base91 table, decoder and caching accessor of
    `test.lib.scripts.js.deobfuscation.test_b91strings`, with the `bufferToString` that fixture
    leaves to its caller written in so that the program runs. Index 12 decodes to `log`.
    """
    return _lines(
        'function bufferToString(a) { return String.fromCharCode.apply(null, a); }',
        'var cache = {};',
        'var table = ["aa","bb","cc","dd","ee","ff","gg","hh","ii","jj",'
        '"fOg=r","lrCD^","#ZlH"];',
        F'{decoder_kw}function decode(str) {{',
        F'    var alpha = "{A_BASE91_ALPHABET}";',
        '    var raw = "" + (str || "");',
        '    var len = raw.length;',
        '    var ret = [];',
        '    var b = 0, n = 0, v = -1;',
        '    for (var i = 0; i < len; i++) {',
        '        var p = alpha.indexOf(raw[i]);',
        '        if (p === -1) continue;',
        '        if (v < 0) { v = p; }',
        '        else {',
        '            v += p * 91;',
        '            b |= v << n;',
        '            n += (v & 8191) > 88 ? 13 : 14;',
        '            do { ret.push(b & 0xff); b >>= 8; n -= 8; } while (n > 7);',
        '            v = -1;',
        '        }',
        '    }',
        '    if (v > -1) { ret.push((b | v << n) & 0xff); }',
        '    return bufferToString(ret);',
        '}',
        F'{accessor_kw}function accessor(index) {{',
        "    if (typeof cache[index] === 'undefined') {",
        '        return cache[index] = decode(table[index]);',
        '    }',
        '    return cache[index];',
        '}',
        F'console.log({read});',
    )


def a_self_disabling_wrapper(kw: str = '', read: str = 'W(a())') -> str:
    return _lines(
        F'{kw}function W() {{ W = function () {{}}; }}',
        'var log = [];',
        "function a() { log.push('a'); return 1; }",
        F'console.log({read}, log.join(","));',
    )


def a_self_disabling_wrapper_as_a_statement(kw: str = '') -> str:
    return _lines(
        F'{kw}function W() {{ W = function () {{}}; }}',
        'var log = [];',
        "function a() { log.push('a'); return 1; }",
        'W(a());',
        'console.log(log.join(","));',
    )


def a_self_disabling_wrapper_called_twice(
    head: str = 'function', read: str = 'typeof W(b())',
) -> str:
    """
    A wrapper called once as a statement and once where its value is read.

    Expanding a call site takes the wrapper's body with it, and that body is the assignment that
    disables the wrapper. The second call therefore reads a wrapper the input had already disabled,
    which for an `async` wrapper answers a promise where the input answered `undefined`. A generator
    is not disabled in the input either, because a call never runs its body.
    """
    return _lines(
        F'{head} W() {{ W = function () {{}}; }}',
        'var log = [];',
        "function a() { log.push('a'); return 1; }",
        "function b() { log.push('b'); return 2; }",
        'W(a());',
        F'console.log({read}, log.join(","));',
    )


def a_self_disabling_wrapper_a_plain_one_shares_a_name_with(
    head: str = 'async function', read: str = 'typeof W(a()).then',
) -> str:
    """
    A wrapper whose call this pass may not answer, under a name a plain wrapper elsewhere in the
    file also answers to. The refusal is kept per declaration, and the plain wrapper's own call is
    expanded all the same: the two calls read two bindings, which their shared name says nothing
    about.
    """
    return _lines(
        'function W() { W = function () {}; }',
        'W(0);',
        'var log = [];',
        "function a() { log.push('a'); return 1; }",
        'function inner() {',
        F'  {head} W() {{ W = function () {{}}; }}',
        F'  return {read};',
        '}',
        'console.log(inner(), log.join(","));',
    )


A_DISPATCH = '(params = ["a", "b"], d("f1"))'


def a_dispatcher(outer: str = '', entry: str = '', read: str = A_DISPATCH) -> str:
    """
    An entry table selected by name behind a dispatcher taking a name, a flag and a return kind.

    The call site reads `(params = [...], d("f1")).then` and never `d("f1").then`: this pass does
    not unwrap the second shape at all, so a row written that way reports agreement for every
    keyword and for the control alike.
    """
    return _lines(
        'var cache = Object["create"](null);',
        'var params;',
        F'{outer}function d(name, flag, rtype, lengths) {{',
        '  var output;',
        F'  var fns = {{ "f1": {entry}function () {{',
        '    var [a, b] = params;',
        '    return a + b;',
        '  } };',
        '  if (flag === "initF") {',
        '    params = [];',
        '  }',
        '  if (flag === "createF") {',
        '    output = cache[name] || (cache[name] = fns[name]);',
        '  } else {',
        '    output = fns[name]();',
        '  }',
        '  if (rtype === "wrapF") {',
        '    return { "wk": output };',
        '  } else {',
        '    return output;',
        '  }',
        '}',
        F'console.log({read});',
    )


#: For each site, the shape that pass exists for and the text it folds to. A guard that refuses more
#: than the keyword is caught here rather than by a suite that stayed green because nothing witnessed
#: the site at all.
THE_SHAPE_EACH_PASS_IS_FOR = {
    'wrappers': (a_call_wrapper(), 'console.log(7);'),
    'simplify': (an_iife(), 'console.log(7);'),
    'globalfinder': (a_global_finder(), 'console.log(globalThis === globalThis);'),
    'interpreter': (a_callback(), 'console.log(1);'),
    'interpreter inside a body': (a_callback_inside_a_body(), 'console.log(1);'),
    'unshuffle': (
        a_rotation(),
        "var x = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j'];"
        + NL + 'console.log(x.join(""));',
    ),
    'stringarray': (a_string_array(), "console.log('hello');"),
    'scramble': (a_scramble(), "console.log(typeof 'https://api.github.com'.then);"),
    'b91strings': (a_base91_table(), "console.log(typeof 'log'.then);"),
    'argwrap in statement position': (
        a_self_disabling_wrapper_as_a_statement(),
        _lines(
            'var log = [];',
            "log.push('a');",
            'console.log(log.join(","));',
        ).rstrip(NL),
    ),
    'argwrap in expression position': (
        a_self_disabling_wrapper(),
        _lines(
            'var log = [];',
            'function a() {',
            "  log.push('a');",
            '  return 1;',
            '}',
            'console.log((a(), void 0), log.join(","));',
        ).rstrip(NL),
    ),
    'dispatcher': (a_dispatcher(), "console.log('ab');"),
}


#: Per site, the same shape with a keyword on the function whose call the pass answers, mapped to
#: what Node prints for it. Every value here was read off Node and none of it off this project.
A_CALL_ANSWERING_A_WRAPPER = {
    'wrappers': {
        a_call_wrapper('async ', 'typeof w(7).then'): 'function\n',
        a_call_wrapper('function* ', 'typeof w(7).next').replace(
            'function* function w', 'function* w'): 'function\n',
        a_call_wrapper('async function* ', 'typeof w(7).next').replace(
            'async function* function w', 'async function* w'): 'function\n',
    },
    'simplify': {
        an_iife('typeof (async function (a) { return a; })(7).then'): 'function\n',
        an_iife('typeof (function* (a) { return a; })(7).next'): 'function\n',
    },
    'globalfinder': {
        a_global_finder('async ', 'typeof g().then'): 'function\n',
        a_global_finder('function* ', 'typeof g().next').replace(
            'function* function g', 'function* g'): 'function\n',
        a_global_finder(
            read='typeof g().then', closure_head='async function'): 'function' + NL,
        a_global_finder(
            read='typeof g().next', closure_head='function*'): 'function' + NL,
    },
    'interpreter': {
        a_callback('[1, 2].filter(async function (x) { return x > 1; }).length'): '2\n',
        a_callback('[1, 2].filter(async (x) => x > 1).length'): '2\n',
        a_callback('[1, 2].filter(function* (x) { return x > 1; }).length'): '2\n',
    },
    'interpreter inside a body': {
        a_callback_inside_a_body('async '): '2\n',
    },
    'unshuffle': {
        a_rotation('async ', 'typeof x.then'): 'function\n',
        a_rotation('function* ', 'typeof x.next').replace(
            'function* function rot', 'function* rot'): 'function\n',
    },
    'stringarray': {
        a_string_array('async ', read='typeof ACC(0).then'): 'function\n',
        a_string_array('function* ', read='typeof ACC(0).next').replace(
            'function* function ACC', 'function* ACC'): 'function\n',
        a_string_array(holder_kw='function* ').replace(
            'function* function A', 'function* A'): 'undefined\n',
    },
    'scramble': {
        a_scramble('async '): 'function\n',
        a_scramble(
            'function* ',
            F"typeof decode('{AN_ENCODED_STRING}').next",
        ).replace('function* function decode', 'function* decode'): 'function\n',
    },
    'b91strings': {
        a_base91_table(accessor_kw='async '): 'function\n',
        a_base91_table(
            accessor_kw='function* ',
            read='typeof accessor(12).next',
        ).replace('function* function accessor', 'function* accessor'): 'function\n',
        a_base91_table(decoder_kw='async '): 'function\n',
    },
    'argwrap in expression position': {
        a_self_disabling_wrapper('async ', 'typeof W(a()).then'): 'function a\n',
        a_self_disabling_wrapper('function* ', 'typeof W(a()).next').replace(
            'function* function W', 'function* W'): 'function a\n',
        a_self_disabling_wrapper_a_plain_one_shares_a_name_with(): 'function a\n',
        a_self_disabling_wrapper_a_plain_one_shares_a_name_with(
            'function*', 'typeof W(a()).next'): 'function a\n',
    },
    'argwrap in statement position': {
        a_self_disabling_wrapper_called_twice('async function'): 'undefined a,b\n',
        a_self_disabling_wrapper_called_twice('function*'): 'object a,b\n',
    },
    'dispatcher': {
        a_dispatcher(outer='async ', read=F'typeof {A_DISPATCH}.then'): 'function\n',
        a_dispatcher(outer='*', read=F'typeof {A_DISPATCH}.next').replace(
            '*function d(', 'function* d(', 1): 'function\n',
    },
}


#: Shapes in which the keyword sits on a function whose call the pass is right to answer, so that a
#: guard written per pass rather than per function is caught. The dispatcher's entries are built
#: with the keyword carried, which `dispatcher._build_extracted_function` already does, and an
#: async arrow immediately called is answered by the value of its own body.
#:
#: The `async` rotation IIFE is the row that says the two kinds do not always answer together: that
#: loop is read for its effect on the array and never for what the call answered, and an `async`
#: body holding no `await` runs to completion before the call returns, so the array really is
#: rotated. Its generator twin, which rotates nothing, sits in
#: `A_ROTATION_THAT_READS_WHAT_THE_HOLDER_ANSWERED`.
A_WRAPPER_THE_PASS_IS_RIGHT_TO_ANSWER = {
    a_string_array_whose_rotation_runs(target=5, rotation_head='async function'): (
        '5' + NL,
        "console.log('5');",
    ),
    an_iife('typeof (async (a) => a)(7).then'): (
        'function' + NL,
        'console.log(typeof (async a => a)(7).then);',
    ),
    a_dispatcher(read=F'typeof {A_DISPATCH}.then'): (
        'undefined' + NL,
        "console.log(typeof 'ab'.then);",
    ),
    a_dispatcher(entry='async ', read=F'typeof {A_DISPATCH}.then'): (
        'function' + NL,
        _lines(
            'async function f1(a, b) {',
            '  return a + b;',
            '}',
            'console.log(typeof f1("a", "b").then);',
        ).rstrip(NL),
    ),
    a_dispatcher(entry='*', read=F'typeof {A_DISPATCH}.next').replace(
        '*function ()', 'function* ()', 1): (
        'function' + NL,
        _lines(
            'function* f1(a, b) {',
            '  return a + b;',
            '}',
            'console.log(typeof f1("a", "b").next);',
        ).rstrip(NL),
    ),
}


#: What Node makes of a string array whose rotation loop actually turns the array over, per kind of
#: each function the three parts are built from. The holder rows say an `async` holder is not an
#: answer the pass may give: the loop indexes what the holder answered, and what an `async` holder
#: answers is a promise, which has no `shift`. Node throws where the pass used to print the rotated
#: string.
#:
#: The replacement rows ask the same of the function the holder installs in its own place, which is
#: what every call after the first reaches, and the rotation row asks it of the loop's own function:
#: calling a generator never runs its body, so the array Node hands the accessor is the one written.
#:
#: The plain row beside them is the control, and it is also why `a_string_array` cannot state this
#: on its own: its loop breaks before it touches the array, so every kind agrees there.
A_ROTATION_THAT_READS_WHAT_THE_HOLDER_ANSWERED = {
    a_string_array_whose_rotation_runs(target=5): ('5' + NL, None),
    a_string_array_whose_rotation_runs('async function', target=5): ('', 'TypeError'),
    a_string_array_whose_rotation_runs('function*', target=5): ('', 'TypeError'),
    a_string_array_whose_rotation_runs(
        target=5, replacement_head='async function'): ('', 'TypeError'),
    a_string_array_whose_rotation_runs(
        target=5, replacement_head='function*'): ('', 'TypeError'),
    a_string_array_whose_rotation_runs(
        target=5, rotation_head='function*'): ('3' + NL, None),
}


#: Programs whose fold lifts an operator out of the body that gives it meaning. Neither output is a
#: program at all: `await` outside an `async` body and `yield` outside a generator are syntax errors,
#: so `refinery.lib.scripts.is_well_formed` answers `False` for what comes back.
AN_OPERATOR_THE_BODY_GAVE_MEANING_TO = (
    'console.log(typeof (async function () { return await 7; })().then);' + NL,
    'console.log(typeof (function* () { return yield 7; })().next);' + NL,
)


#: Every way the language has of writing a function, against the kind each one is: whether it is
#: `async`, whether it is a generator, and whether a call to it therefore answers a wrapper rather
#: than what the body returned. The answers are the syntax and nothing else — `async function*` is
#: both, an arrow is never a generator because none can be written.
A_FUNCTION_OF_EVERY_KIND = {
    'function f() {}': (False, False, False),
    'async function f() {}': (True, False, True),
    'function* f() {}': (False, True, True),
    'async function* f() {}': (True, True, True),
    '(function () {});': (False, False, False),
    '(async function () {});': (True, False, True),
    '(function* () {});': (False, True, True),
    '(async function* () {});': (True, True, True),
    '(() => 0);': (False, False, False),
    '(async () => 0);': (True, False, True),
    '({ m() {} });': (False, False, False),
    '({ async m() {} });': (True, False, True),
    '({ *m() {} });': (False, True, True),
    '({ async *m() {} });': (True, True, True),
    '(class { async m() {} });': (True, False, True),
    '(class { *m() {} });': (False, True, True),
}


def _the_only_function_in(source: str) -> JsFunctionNode:
    root = JsParser(source).parse()
    functions = [node for node in root.walk() if isinstance(node, FUNCTION_NODES)]
    if len(functions) != 1:
        raise AssertionError(F'{source!r} holds {len(functions)} functions, not one')
    return functions[0]


def _the_kind_the_predicates_answer(source: str) -> tuple[bool, bool, bool]:
    func = _the_only_function_in(source)
    return (
        is_async_function(func),
        is_generator_function(func),
        wraps_return(func),
    )


def _wraps_what_it_returns(node: Node | None) -> bool:
    return isinstance(node, FUNCTION_NODES) and bool(
        getattr(node, 'is_async', False) or getattr(node, 'generator', False)
    )


def _the_keys_a_wrapping_function_is_held_under(root: Node) -> set[str]:
    """
    Every name a wrapping function in *root* is held under: its own, the one a declarator binds it
    to, and the property or method key it is written at. A member access names no binding, so a name
    a wrapping function carries anywhere is all a reading of the text can say about `o.m()`.
    """
    names: set[str] = set()
    for node in root.walk():
        if not _wraps_what_it_returns(node):
            continue
        own = getattr(node, 'id', None)
        if isinstance(own, JsIdentifier):
            names.add(own.name)
        owner = node.parent
        if isinstance(owner, JsVariableDeclarator) and isinstance(owner.id, JsIdentifier):
            names.add(owner.id.name)
        if isinstance(owner, (JsProperty, JsMethodDefinition)):
            key = getattr(owner, 'key', None)
            if isinstance(key, JsIdentifier):
                names.add(key.name)
            elif isinstance(key, JsStringLiteral):
                names.add(key.value)
    return names


def _the_names_a_pattern_binds(pattern: Node | None) -> set[str]:
    """
    The names a binding position introduces: the identifier itself, the target a default is written
    onto, what a rest element gathers, and the value halves of an object or array pattern. A
    property key that is not the pattern's own identifier names a property and binds nothing.
    """
    if isinstance(pattern, JsIdentifier):
        return {pattern.name}
    if isinstance(pattern, JsAssignmentPattern):
        return _the_names_a_pattern_binds(pattern.left)
    if isinstance(pattern, JsRestElement):
        return _the_names_a_pattern_binds(pattern.argument)
    names: set[str] = set()
    if isinstance(pattern, JsArrayPattern):
        for element in pattern.elements:
            names |= _the_names_a_pattern_binds(element)
    if isinstance(pattern, JsObjectPattern):
        for entry in pattern.properties:
            names |= _the_names_a_pattern_binds(
                entry.value if isinstance(entry, JsProperty) else entry)
    return names


def _the_scopes_around(node: Node):
    owner = node.parent
    while owner is not None:
        if isinstance(owner, (JsScript, *FUNCTION_NODES)):
            yield owner
        owner = owner.parent


def _the_region_a_holder_scopes(holder: Node | None) -> Node | None:
    """
    The node a block-scoped declaration written directly in *holder* is visible throughout. Every
    case of a `switch` shares the one scope the switch block opens, so a `let` written in one case
    is visible in all of them and in the discriminant of none.
    """
    return holder.parent if isinstance(holder, JsSwitchCase) else holder


def _where_a_lexical_declaration_is_visible(node: Node) -> Node | None:
    """
    The region a declaration is visible in when it is visible in less than the whole scope — a
    `let`, a `const`, a class, or a caught error — and `None` for one the whole scope holds.
    """
    if isinstance(node, JsCatchClause):
        return node.body
    if isinstance(node, JsClassDeclaration):
        return _the_region_a_holder_scopes(node.parent)
    if isinstance(node, JsVariableDeclarator):
        declaration = node.parent
        if isinstance(declaration, JsVariableDeclaration) and declaration.kind is not JsVarKind.VAR:
            return _the_region_a_holder_scopes(declaration.parent)
    return None


def _what_a_declaration_binds(node: Node) -> tuple[set[str], Node | None]:
    """
    The names *node* declares and what it binds them to, which is `None` for a declaration binding
    something other than a function written where it stands.
    """
    if isinstance(node, JsFunctionDeclaration) and isinstance(node.id, JsIdentifier):
        return {node.id.name}, node
    if isinstance(node, JsClassDeclaration) and isinstance(node.id, JsIdentifier):
        return {node.id.name}, None
    if isinstance(node, JsVariableDeclarator):
        return _the_names_a_pattern_binds(node.id), node.init
    if isinstance(node, JsCatchClause):
        return _the_names_a_pattern_binds(node.param), None
    if isinstance(
        node, (JsImportSpecifier, JsImportDefaultSpecifier, JsImportNamespaceSpecifier)
    ):
        return _the_names_a_pattern_binds(node.local), None
    return set(), None


def _how_deep_inside(scope: Node, block: Node | None) -> int:
    """
    How far *block* sits below *scope*, and zero for a declaration the whole scope holds. Where one
    name is declared twice, the deeper of the two is the one a reference inside both reads.
    """
    depth = 0
    node = block
    while node is not None and node is not scope:
        depth += 1
        node = node.parent
    return depth


def _what_a_scope_declares(scope: Node, name: str, reference: JsIdentifier) -> list[Node | None]:
    """
    What *scope* itself declares under *name* where *reference* stands: a function expression's own
    name, the parameters, and the declarations written in it, less the ones a block holds that the
    reference stands outside of. A function below the scope declares into its own scope, not this
    one.
    """
    seen: list[tuple[int, Node | None]] = []
    if isinstance(scope, JsFunctionExpression) and isinstance(scope.id, JsIdentifier):
        if scope.id.name == name:
            seen.append((0, scope))
    for parameter in getattr(scope, 'params', None) or ():
        if name in _the_names_a_pattern_binds(parameter):
            seen.append((0, None))
    for node in scope.walk():
        if node is scope or next(_the_scopes_around(node), None) is not scope:
            continue
        names, bound = _what_a_declaration_binds(node)
        if name not in names:
            continue
        block = _where_a_lexical_declaration_is_visible(node)
        if block is not None and not reference.is_descendant_of(block):
            continue
        seen.append((_how_deep_inside(scope, block), bound))
    if not seen:
        return []
    innermost = max(depth for depth, _ in seen)
    return [bound for depth, bound in seen if depth == innermost]


def _what_a_scope_writes(scope: Node, name: str) -> list[Node | None]:
    """
    What an assignment written anywhere in *scope* puts into the binding *scope* declares under
    *name*. A declaration says what a name is bound to and an assignment says what it holds later,
    and a call reads whichever of the two ran last, so both count.

    An assignment a nested scope declaring the same name owns puts nothing into this binding, so the
    target is resolved the same way a read is: the innermost scope around it that declares the name
    at all has to be this one.
    """
    written: list[Node | None] = []
    for node in scope.walk():
        if not isinstance(node, JsAssignmentExpression) or not isinstance(node.left, JsIdentifier):
            continue
        if node.left.name != name:
            continue
        if _the_scope_the_name_reaches(node.left) is not scope:
            continue
        written.append(node.right)
    return written


def _the_scope_the_name_reaches(reference: JsIdentifier) -> Node | None:
    """
    The innermost scope around *reference* that declares its name at all, which is the one a read or
    a write of it touches, and `None` for a name declared nowhere.
    """
    for scope in _the_scopes_around(reference):
        if _what_a_scope_declares(scope, reference.name, reference):
            return scope
    return None


def _the_name_reaches_a_wrapping_function(reference: JsIdentifier) -> bool:
    """
    Whether the name read at *reference* reaches a function that wraps what its body returns, read
    the way a reader reads it: the innermost scope around the reference that declares the name at
    all is the one that answers, and a name declared nowhere reaches nothing.

    A file-global set of the names a wrapping function answers to cannot say this. It counts a call
    to a plain function elsewhere in the file as a call to the wrapping one, so a pass that answers
    the plain call — which it may — reads as having answered the wrapping one.
    """
    scope = _the_scope_the_name_reaches(reference)
    if scope is None:
        return False
    return any(
        _wraps_what_it_returns(node)
        for node in (
            *_what_a_scope_declares(scope, reference.name, reference),
            *_what_a_scope_writes(scope, reference.name),
        )
    )


def _calls_a_wrapping_function(callee: Node | None, keys: set[str]) -> bool:
    if _wraps_what_it_returns(callee):
        return True
    if isinstance(callee, JsIdentifier):
        return _the_name_reaches_a_wrapping_function(callee)
    if isinstance(callee, JsMemberExpression) and not callee.computed:
        key = callee.property
        return isinstance(key, JsIdentifier) and key.name in keys
    return False


def _what_wraps_and_what_calls_it(source: str) -> tuple[int, int]:
    """
    How many functions in *source* wrap what their body returns, and how many calls reach one.

    A pass that answers such a call takes the call away, and usually the function with it, so this
    pair moving is what a wrong answer looks like from outside the engine. A pass that reshapes
    either without answering the call — promoting an accessor, flattening a namespace, extracting an
    entry — carries the keyword along and leaves the pair where it was.
    """
    root = JsParser(source).parse()
    keys = _the_keys_a_wrapping_function_is_held_under(root)
    wrapping = 0
    calls = 0
    for node in root.walk():
        if _wraps_what_it_returns(node):
            wrapping += 1
        if isinstance(node, JsCallExpression) and _calls_a_wrapping_function(node.callee, keys):
            calls += 1
    return wrapping, calls


def _each_row_keeps_what_wraps_and_what_calls_it(rows: dict[str, str]) -> dict[str, tuple[int, int]]:
    return {source: _what_wraps_and_what_calls_it(source) for source in rows}


def _after_the_fold(rows: dict[str, str]) -> dict[str, tuple[int, int]]:
    return {source: _what_wraps_and_what_calls_it(folded(source)) for source in rows}


class TestEachPassStillAnswersTheShapeItIsFor(TestBase):
    """
    The admission control, one row per site, with no keyword anywhere. Each states the text that pass
    folds its own shape to, so that a guard which refuses the shape rather than the keyword fails
    here. Without it a guard could empty a site and leave the suite green, which is what
    `stringarray._match_wrapper` is witnessed by nothing enough to allow.
    """

    def test_every_site_folds_the_shape_it_exists_for(self):
        self.assertEqual(
            {site: folded(source) for site, (source, _) in THE_SHAPE_EACH_PASS_IS_FOR.items()},
            {site: text for site, (_, text) in THE_SHAPE_EACH_PASS_IS_FOR.items()},
        )


class TestAWrapperThePassIsRightToAnswerIsStillAnswered(TestBase):
    """
    The other half of the control: a keyword on a function whose call the pass may answer. A guard
    written per pass rather than per function destroys these.
    """

    def test_each_of_them_folds_to_the_text_it_folded_to(self):
        rows = A_WRAPPER_THE_PASS_IS_RIGHT_TO_ANSWER
        self.assertEqual(
            {source: folded(source) for source in rows},
            {source: text for source, (_, text) in rows.items()},
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_each_of_them_prints_what_it_printed(self):
        rows = {
            source: prints
            for source, (prints, _) in A_WRAPPER_THE_PASS_IS_RIGHT_TO_ANSWER.items()
        }
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


class TestTheDeobfuscationStillCallsAWrappingFunction(TestBase):
    """
    What each site leaves standing, read from the output text and from nothing else, so that the
    regression is reported on a machine with no Node.js as well.
    """

    def test_no_site_answers_a_call_to_one(self):
        rows = {
            source: prints
            for group in A_CALL_ANSWERING_A_WRAPPER.values()
            for source, prints in group.items()
        }
        self.assertEqual(_after_the_fold(rows), _each_row_keeps_what_wraps_and_what_calls_it(rows))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestTheProgramPrintsWhatItPrinted(TestBase):
    """
    Node is the oracle for every value here. Each test names what Node prints and asserts that the
    deobfuscation prints it too, with neither of the two throwing.
    """

    def test_a_call_wrapper(self):
        """
        Node prints `function` for each: `w(7)` answers a promise for `async`, a generator object for
        a generator, and an async generator object for both, and each has the read the row asks for.
        """
        rows = A_CALL_ANSWERING_A_WRAPPER['wrappers']
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_an_iife(self):
        rows = A_CALL_ANSWERING_A_WRAPPER['simplify']
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_global_finder(self):
        rows = A_CALL_ANSWERING_A_WRAPPER['globalfinder']
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_callback_an_array_method_runs(self):
        """
        Node prints `2` for each: every promise and every generator object is truthy, so `filter`
        keeps both elements where the value each body returned would have kept one.
        """
        rows = A_CALL_ANSWERING_A_WRAPPER['interpreter']
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_callback_inside_a_function_body(self):
        rows = A_CALL_ANSWERING_A_WRAPPER['interpreter inside a body']
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_rotation(self):
        rows = A_CALL_ANSWERING_A_WRAPPER['unshuffle']
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_string_array(self):
        """
        Node prints `function` for the two accessor rows. The generator *holder* prints `undefined`:
        a generator's body does not run when it is called, so the self-reassignment never happens and
        the accessor reads an index of a generator object.
        """
        rows = A_CALL_ANSWERING_A_WRAPPER['stringarray']
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_scramble_decoder(self):
        rows = A_CALL_ANSWERING_A_WRAPPER['scramble']
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_base91_table(self):
        """
        The keyword is asked for on the accessor and on the decoder, because the accessor answers
        with what the decoder gave it and either one wrapping is enough to make the call answer a
        wrapper.
        """
        rows = A_CALL_ANSWERING_A_WRAPPER['b91strings']
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_self_disabling_wrapper_in_expression_position(self):
        """
        Node prints `function a`: the call answers a promise, and the argument ran on the way. The
        expansion writes `(a(), void 0)`, which has the argument's effect and no `.then`.
        """
        rows = A_CALL_ANSWERING_A_WRAPPER['argwrap in expression position']
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_self_disabling_wrapper_in_statement_position(self):
        """
        Node prints `undefined a,b` for the `async` wrapper: its body ran on the first call and
        disabled it, so the second call answers `undefined`. Expanding the first call takes that
        body away, and the second call then answers a promise. The generator beside it prints
        `object a,b` because a call never runs its body, so nothing disables it either way.
        """
        rows = A_CALL_ANSWERING_A_WRAPPER['argwrap in statement position']
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_dispatcher(self):
        rows = A_CALL_ANSWERING_A_WRAPPER['dispatcher']
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


class TestNeitherEscapeLeavesAProgramNothingCanSpell(TestBase):
    """
    `await` and `yield` mean what they mean because of the body they stand in. Lifting the body's
    return expression to the call site would take that body away, and what came back would not be a
    program at all: `await` outside an `async` body and `yield` outside a generator are both syntax
    errors. `refinery.lib.scripts.is_well_formed`, reached through
    `test.lib.scripts.js.ledger.well_formed`, answers for what comes back.
    """

    def test_the_fold_leaves_both_of_them_spellable(self):
        self.assertEqual(
            [well_formed(folded(source)) for source in AN_OPERATOR_THE_BODY_GAVE_MEANING_TO],
            [True, True],
        )


class TestARefusalStillLetsTheRunEnd(TestBase):
    """
    A pass that declines has to decline without reporting a change, or the pipeline is handed the
    same tree for as long as it is willing to look at it. Every shape the guards refuse is run under
    a bound here, so a refusal that spins is a failure and not a hang.
    """

    def test_every_refused_shape_is_deobfuscated_within_the_bound(self):
        rows = [
            source
            for group in A_CALL_ANSWERING_A_WRAPPER.values()
            for source in group
        ]
        self.assertEqual(
            [deobfuscate_within(source, 30.0) is not None for source in rows],
            [True] * len(rows),
        )


class TestTheKindOfAFunctionIsAnsweredForEverySpellingOfOne(TestBase):
    """
    The three predicates the guards are written in terms of, asked for every way the language has of
    writing a function. An arrow carries no `generator` field at all, because there is no generator
    arrow to write, so the generator question has to be answered for one without reading it.
    """

    def test_each_spelling_answers_the_kind_it_is_written_with(self):
        self.assertEqual(
            {
                source: _the_kind_the_predicates_answer(source)
                for source in A_FUNCTION_OF_EVERY_KIND
            },
            A_FUNCTION_OF_EVERY_KIND,
        )

    def test_wrapping_is_exactly_being_async_or_being_a_generator(self):
        self.assertEqual(
            {
                source: wraps_return(_the_only_function_in(source))
                for source in A_FUNCTION_OF_EVERY_KIND
            },
            {
                source: is_async or is_generator
                for source, (is_async, is_generator, _) in A_FUNCTION_OF_EVERY_KIND.items()
            },
        )


#: Programs calling a function the `async` keyword marks, mapped to what Node prints for each.
#: Calling one answers a promise whose resolution is the value the body returned, never that value,
#: so a program asking anything of what the call answered is asking it of the promise. Two of the
#: three were folded to the returned value until the call wrapper and the IIFE inliner began asking
#: what a call answers.
A_CALL_TO_AN_ASYNC_FUNCTION = {
    'async function m(){ return 7; }'
    ' m().then(function(v){ console.log(v); });': '7\n',
    'var o = { async m(){ return 7; } };'
    ' console.log(typeof o.m().then);': 'function\n',
    'async function m(){ return 7; }'
    ' console.log(m() instanceof Promise);': 'true\n',
}


#: The same rule reached through the other spellings of a function: an async function expression, an
#: async arrow, an async method of a class, and a generator method. These were answered correctly
#: before the fold learned the rule, so they say the fix did not buy one spelling at another's cost.
AN_ASYNC_SHAPE_WRITTEN_ANOTHER_WAY = {
    'var m = async function(){ return 7; }; console.log(typeof m().then);': 'function\n',
    'var m = async () => 7; console.log(typeof m().then);': 'function\n',
    'class C { async m(){ return 7; } } console.log(typeof new C().m().then);': 'function\n',
    'var o = { *m(){ yield 7; } }; console.log(o.m().next().value);': '7\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnAsyncCallAnswersAPromiseInEverySpelling(TestBase):
    """
    The rows the release ledger carried as a blocker until the two general inliners began asking what
    a call answers, and the four spellings beside them that were never folded. Each row asks the call
    for something only the promise or the generator object has, so a fold to the returned value
    prints something else or throws where Node prints a value.
    """

    def test_a_call_to_an_async_function_is_not_folded_to_what_its_body_returned(self):
        self.assertEqual(
            {
                source: before_and_after(source)
                for source in A_CALL_TO_AN_ASYNC_FUNCTION
            },
            each_program_still_prints(A_CALL_TO_AN_ASYNC_FUNCTION),
        )

    def test_an_async_function_written_another_way_prints_what_it_printed(self):
        self.assertEqual(
            {
                source: before_and_after(source)
                for source in AN_ASYNC_SHAPE_WRITTEN_ANOTHER_WAY
            },
            each_program_still_prints(AN_ASYNC_SHAPE_WRITTEN_ANOTHER_WAY),
        )


#: Every route by which the deobfuscation reaches `JsInterpreter._call_function`, with a plain
#: function at the end of it, mapped to what Node prints and what the deobfuscation folds it to. The
#: guard added there is one line nine callers share, so a guard refusing more than the keyword empties
#: all of them at once.
#:
#: `_eval_inline_call` has no row: traced over the whole harvest it is never entered, because an
#: immediately called function expression is folded before the interpreter is asked about it. A row
#: written for it would report the guard admits what it should while never reaching the guard.
A_CALL_THE_INTERPRETER_MAY_RUN = {
    'console.log((function () { var g = function (a) { return a + a; };'
    ' var s = 0; for (var i = 0; i < 2; i++) s += g(i); return s; })());': (
        '2' + NL, 'console.log(2);'),
    'function t(a) { return a + a; }'
    ' console.log((function () { var s = 0;'
    ' for (var i = 0; i < 2; i++) s += t(i); return s; })());': (
        '2' + NL, 'console.log(2);'),
    'console.log((function () { var g = function (a) { return a + a; };'
    ' var s = 0; for (var i = 0; i < 2; i++) s += g.call(null, i); return s; })());': (
        '2' + NL, 'console.log(2);'),
    'console.log((function () { var g = function (a) { return a + a; };'
    ' var s = 0; for (var i = 0; i < 2; i++) s += g.apply(null, [i]); return s; })());': (
        '2' + NL, 'console.log(2);'),
    'console.log([1, 2].every(function (x) { return x > 0; }));': (
        'true' + NL, 'console.log(true);'),
    'console.log([1, 2].some(function (x) { return x > 1; }));': (
        'true' + NL, 'console.log(true);'),
    'console.log([1, 2].map(function (x) { return x + 1; }).join(","));': (
        '2,3' + NL, "console.log('2,3');"),
    'console.log([1, 2].filter(function (x) { return x > 1; }).length);': (
        '1' + NL, 'console.log(1);'),
    'console.log([1, 2].find(function (x) { return x > 1; }));': (
        '2' + NL, 'console.log(2);'),
    'console.log([1, 2].findIndex(function (x) { return x > 1; }));': (
        '1' + NL, 'console.log(1);'),
    'function f() { var n = [1, 2].length;'
    ' [1, 2].forEach(function (x) { return x; }); return n; }'
    ' console.log(f());': (
        '2' + NL, 'console.log(2);'),
    'console.log([1, 2].reduce(function (a, x) { return a + x; }, 0));': (
        '3' + NL, 'console.log(3);'),
}


def _folded_while_watching_the_interpreter(source: str) -> tuple[str, bool]:
    """
    What *source* folds to, and whether the guarded call was entered while it folded.
    """
    original = JsInterpreter._call_function
    entered: list[object] = []

    def counted(interpreter, func, args):
        entered.append(func)
        return original(interpreter, func, args)

    JsInterpreter._call_function = counted
    try:
        return folded(source), bool(entered)
    finally:
        JsInterpreter._call_function = original


class TestTheInterpreterStillRunsACallItMayRun(TestBase):
    """
    The admission control for the guard on the interpreter's trunk. Each row states the text it folds
    to, and states that the guarded method was entered while it folded — without the second, a row
    some other pass began answering would go on reporting that the guard admits what it should.
    """

    def test_each_route_folds_to_the_text_it_folds_to(self):
        self.assertEqual(
            {
                source: _folded_while_watching_the_interpreter(source)[0]
                for source in A_CALL_THE_INTERPRETER_MAY_RUN
            },
            {source: text for source, (_, text) in A_CALL_THE_INTERPRETER_MAY_RUN.items()},
        )

    def test_each_route_reaches_the_guarded_call(self):
        self.assertEqual(
            {
                source: _folded_while_watching_the_interpreter(source)[1]
                for source in A_CALL_THE_INTERPRETER_MAY_RUN
            },
            {source: True for source in A_CALL_THE_INTERPRETER_MAY_RUN},
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestEveryRouteIntoTheInterpreterPrintsWhatItPrinted(TestBase):
    """
    The same rows against Node, so that a fold which keeps its shape but changes its value is caught.
    """

    def test_each_route_prints_what_it_printed(self):
        rows = {
            source: prints
            for source, (prints, _) in A_CALL_THE_INTERPRETER_MAY_RUN.items()
        }
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestARotationReadsWhatTheHolderAnswered(TestBase):
    """
    The string array's holder is called by the rotation loop before anything else reads it, and the
    loop indexes what it answered. A holder that answers a promise or a generator object makes that
    indexing throw, so a pass that resolved the strings anyway handed back a program that runs where
    the input did not.
    """

    def test_each_kind_of_holder_does_what_it_does(self):
        rows = A_ROTATION_THAT_READS_WHAT_THE_HOLDER_ANSWERED
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            {source: (answer, answer) for source, answer in rows.items()},
        )
