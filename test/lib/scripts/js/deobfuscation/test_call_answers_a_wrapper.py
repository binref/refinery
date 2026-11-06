"""
A call to an `async` function or a generator answers a wrapper, a promise or a generator object, and
never the value its body returns.

Every row reads something only the wrapper has: `.then` for an `async` function, `.next` for a
generator and for an async generator. A generator object has no `.then` either, so `typeof g().then`
prints `undefined` whether or not the call was folded.

The count of functions that wrap and of calls that reach one is read from the syntax in this file
and never asked of the library, so that a wrong answer of the library cannot hide from it.

SECURITY: the programs here run in Node, and every one is written out in full in this file. No
sample and no stored obfuscator fixture may ever be added here.
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
    return _lines(
        F'{kw}function g() {{',
        F'  var a = [{closure_head} () {{ return globalThis; }}];',
        '  var r = a[0]();',
        '  return r;',
        '}',
        F'console.log({read});',
    )


def a_callback(read: str = '[1, 2].filter(function (x) { return x > 1; }).length') -> str:
    return _lines(F'console.log({read});')


def a_callback_inside_a_body(kw: str = '') -> str:
    return _lines(
        'function f() {',
        F'  return [1, 2].filter({kw}function (x) {{ return x > 1; }}).length;',
        '}',
        'console.log(f());',
    )


def a_rotation(kw: str = '', read: str = 'x.join("")') -> str:
    return _lines(
        F'{kw}function rot(arr, n) {{',
        '  for (var i = 0; i < n; i++) arr.push(arr.shift());',
        '  return arr;',
        '}',
        'var x = rot(["b", "c", "d", "e", "f", "g", "h", "i", "j", "a"], 9);',
        F'console.log({read});',
    )


def a_string_array(accessor_kw: str = '', holder_kw: str = '', read: str = 'ACC(0)') -> str:
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
    return _lines(
        'var cache = Object["create"](null);',
        'var params;',
        F'{outer}function d(name, flag, rtype, lengths = {{}}) {{',
        '  var output;',
        F'  var fns = {{ "f1": {entry}function () {{',
        '    var [a, b] = params;',
        '    return a + b;',
        '  } };',
        '  if (flag === "clearF") {',
        '    params = [];',
        '  }',
        '  if (flag === "createF") {',
        '    function createFunction() {',
        '      var fn = function (...args) {',
        '        params = args;',
        '        return fns[name].apply(this);',
        '      };',
        '      var fnLength = lengths[name];',
        '      if (fnLength) {',
        '        setLength(fn, fnLength);',
        '      }',
        '      return fn;',
        '    }',
        '    output = cache[name] || (cache[name] = createFunction());',
        '  } else {',
        '    output = fns[name]();',
        '  }',
        '  if (rtype === "wrapF") {',
        '    return { "wk": output };',
        '  } else {',
        '    return output;',
        '  }',
        '}',
        'function setLength() {}',
        F'console.log({read});',
    )


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
    'scramble': (a_scramble(), "console.log('undefined');"),
    'b91strings': (a_base91_table(), "console.log('undefined');"),
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
        a_dispatcher(entry='*', read=F'typeof {A_DISPATCH}.next').replace(
            '*function ()',
            'function* ()',
            1,
        ): 'function\n',
    },
}


#: An `async` function holding no `await` runs its whole body before its call returns, so the
#: `async` rotation turns the array over just as a plain one does.
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
        "console.log('undefined');",
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
}


#: Where the holder or the function it installs in its place is `async` or a generator, the loop's
#: `arr` is a promise or a generator object, which has neither `push` nor `shift`, so the program
#: throws a `TypeError`. A generator rotation prints `3` because calling a generator never runs its
#: body, so the array is never turned over.
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


AN_OPERATOR_THE_BODY_GAVE_MEANING_TO = (
    'console.log(typeof (async function () { return await 7; })().then);' + NL,
    'console.log(typeof (function* () { return yield 7; })().next);' + NL,
)


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
    The node throughout which a block-scoped declaration written directly in *holder* is visible.
    All cases of a `switch` share the one scope its block opens, so a `let` written in one case is
    visible in every case.
    """
    return holder.parent if isinstance(holder, JsSwitchCase) else holder


def _where_a_lexical_declaration_is_visible(node: Node) -> Node | None:
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
    depth = 0
    node = block
    while node is not None and node is not scope:
        depth += 1
        node = node.parent
    return depth


def _what_a_scope_declares(scope: Node, name: str, reference: JsIdentifier) -> list[Node | None]:
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
    for scope in _the_scopes_around(reference):
        if _what_a_scope_declares(scope, reference.name, reference):
            return scope
    return None


def _the_name_reaches_a_wrapping_function(reference: JsIdentifier) -> bool:
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

    def test_every_site_folds_the_shape_it_exists_for(self):
        self.assertEqual(
            {site: folded(source) for site, (source, _) in THE_SHAPE_EACH_PASS_IS_FOR.items()},
            {site: text for site, (_, text) in THE_SHAPE_EACH_PASS_IS_FOR.items()},
        )


class TestAWrapperThePassIsRightToAnswerIsStillAnswered(TestBase):

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

    def test_every_site_but_a_wrapper_called_as_a_statement_keeps_each_call_to_one(self):
        rows = {
            source: prints
            for site, group in A_CALL_ANSWERING_A_WRAPPER.items()
            if site != 'argwrap in statement position'
            for source, prints in group.items()
        }
        self.assertEqual(_after_the_fold(rows), _each_row_keeps_what_wraps_and_what_calls_it(rows))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestTheProgramPrintsWhatItPrinted(TestBase):

    def test_a_call_wrapper(self):
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
        Node prints `2` for each: a promise and a generator object are both truthy, so `filter`
        keeps both elements.
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
        The generator holder prints `undefined`: calling a generator never runs its body, so the
        holder never replaces itself and the accessor indexes a generator object.
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
        rows = A_CALL_ANSWERING_A_WRAPPER['b91strings']
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_self_disabling_wrapper_in_expression_position(self):
        rows = A_CALL_ANSWERING_A_WRAPPER['argwrap in expression position']
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_self_disabling_wrapper_in_statement_position(self):
        """
        Node prints `undefined a,b` for the `async` wrapper: its body runs at the first call and
        replaces it with a plain function, so the second call answers `undefined`. The generator
        prints `object a,b` because calling a generator never runs its body, so it is never
        replaced.
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

    def test_the_fold_leaves_both_of_them_spellable(self):
        self.assertEqual(
            [well_formed(folded(source)) for source in AN_OPERATOR_THE_BODY_GAVE_MEANING_TO],
            [True, True],
        )


class TestARefusalStillLetsTheRunEnd(TestBase):

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

    def test_each_spelling_answers_the_kind_it_is_written_with(self):
        self.assertEqual(
            {
                source: _the_kind_the_predicates_answer(source)
                for source in A_FUNCTION_OF_EVERY_KIND
            },
            A_FUNCTION_OF_EVERY_KIND,
        )


A_CALL_TO_AN_ASYNC_FUNCTION = {
    'async function m(){ return 7; }'
    ' m().then(function(v){ console.log(v); });': '7\n',
    'var o = { async m(){ return 7; } };'
    ' console.log(typeof o.m().then);': 'function\n',
    'async function m(){ return 7; }'
    ' console.log(m() instanceof Promise);': 'true\n',
}


AN_ASYNC_SHAPE_WRITTEN_ANOTHER_WAY = {
    'var m = async function(){ return 7; }; console.log(typeof m().then);': 'function\n',
    'var m = async () => 7; console.log(typeof m().then);': 'function\n',
    'class C { async m(){ return 7; } } console.log(typeof new C().m().then);': 'function\n',
    'var o = { *m(){ yield 7; } }; console.log(o.m().next().value);': '7\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnAsyncCallAnswersAPromiseInEverySpelling(TestBase):

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


class TestTheInterpreterStillRunsACallItMayRun(TestBase):

    def test_each_route_folds_to_the_text_it_folds_to(self):
        self.assertEqual(
            {source: folded(source) for source in A_CALL_THE_INTERPRETER_MAY_RUN},
            {source: text for source, (_, text) in A_CALL_THE_INTERPRETER_MAY_RUN.items()},
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestEveryRouteIntoTheInterpreterPrintsWhatItPrinted(TestBase):

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

    def test_each_kind_of_holder_does_what_it_does(self):
        rows = A_ROTATION_THAT_READS_WHAT_THE_HOLDER_ANSWERED
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            {source: (answer, answer) for source, answer in rows.items()},
        )
