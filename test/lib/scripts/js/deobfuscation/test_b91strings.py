from __future__ import annotations

import base64
import functools
import inspect
import lzma
import unittest

from test import fastest_processor_time, processor_time_ratio
from test.lib.scripts.js.analysis.differential import (
    completion_values,
    deobfuscate_source,
    module_graph_behavior,
    node_executable,
)
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator
from test.lib.scripts.js.ledger import (
    before_and_after,
    before_and_after_in_a_host,
    each_program_still_prints,
)

from refinery.lib.scripts.js.deobfuscation.b91strings import JsBase91StringDecoder, _decode_base91
from refinery.lib.scripts.js.options import DeobfuscationOptions, ExecutionModel
from refinery.lib.scripts.js.parser import JsParser

ALPHABET = '0,Fz)`Q(lH=j5gK[i8~mJt_b&qr/fW^Y2]?#|@.!$cLZ9BN>A1o7ye+D%IM}O6;pV:P*E3CRnxXSh{wvaTUuk4G"s<d'

#: A table of strings encoded with `ALPHABET`: 'fOg=r' is 'push', 'lrCD^' is 'Fizz', '#ZlH' is
#: 'log'.
TABLE = '["aa","bb","cc","dd","ee","ff","gg","hh","ii","jj","fOg=r","lrCD^","#ZlH"]'

#: `TABLE` with 'eww6zXGM(' at index 11, which encodes a byte order mark followed by 'Fizz'.
TABLE_WITH_A_BYTE_ORDER_MARK = '["aa","bb","cc","dd","ee","ff","gg","hh","ii","jj","fOg=r","eww6zXGM(","#ZlH"]'

#: `TABLE` with '{<@g2' at index 0, which encodes U+1F600, a character above the basic plane that a
#: string holds as two code units.
TABLE_WITH_AN_ASTRAL_CHARACTER = '["{<@g2","bb","cc","dd","ee","ff","gg","hh","ii","jj","fOg=r","lrCD^","#ZlH"]'

#: Another table of the same length, with 'Fizz' at index 10.
OTHER_TABLE = '["a","b","c","d","e","f","g","h","i","j","lrCD^","#ZlH","fOg=r"]'

#: The function turning the decoded bytes into a string through `Buffer`.
BUFFER = 'function bufferToString(b) { return Buffer.from(b).toString("utf-8"); }'

#: The function turning the decoded bytes into a string through `TextDecoder`, which drops a leading
#: byte order mark.
TEXT_DECODER = 'function bufferToString(b) { return new TextDecoder()["decode"](new Uint8Array(b)); }'

#: The function turning the decoded bytes into a string with nothing a host has to supply, for a
#: program run where neither `Buffer` nor `TextDecoder` exists.
CHAR_CODES = 'function bufferToString(b) { return String.fromCharCode.apply(null, b); }'

#: The cache and the table every accessor below reads, and the function turning bytes into a string.
HEAD = F'var cache = {{}};\nvar table = {TABLE};\n{BUFFER}\n'


def decoder_body(alphabet: str = ALPHABET) -> str:
    """
    The body of a decoder over *alphabet*, as the obfuscator writes it.
    """
    alphabet = alphabet.replace('"', '\\"')
    return (
        F'var alpha = "{alphabet}"; var raw = "" + (str || ""); var len = raw.length; var ret = []; '
        'var b = 0, n = 0, v = -1; for (var i = 0; i < len; i++) { var p = alpha.indexOf(raw[i]); '
        'if (p === -1) continue; if (v < 0) { v = p; } else { v += p * 91; b |= v << n; '
        'n += (v & 8191) > 88 ? 13 : 14; do { ret.push(b & 0xff); b >>= 8; n -= 8; } while (n > 7); '
        'v = -1; } } if (v > -1) { ret.push((b | v << n) & 0xff); } return bufferToString(ret);'
    )


def decoder(name: str, alphabet: str = ALPHABET) -> str:
    """
    A decoder over *alphabet* declared as *name*.
    """
    return F'function {name}(str) {{ {decoder_body(alphabet)} }}'


def accessor_body(cache: str, decode: str, table: str = 'table') -> str:
    """
    The body of an accessor over *cache*, *decode* and *table*, as the obfuscator writes it.
    """
    return (
        F'if (typeof {cache}[index] === "undefined") {{ return {cache}[index] = {decode}({table}[index]); }} '
        F'return {cache}[index];'
    )


def accessor(name: str, cache: str, decode: str, table: str = 'table') -> str:
    """
    An accessor over *cache*, *decode* and *table* declared as *name*.
    """
    return F'function {name}(index) {{ {accessor_body(cache, decode, table)} }}'


#: One long string holding strings encoded with `ALPHABET` between other characters: 'push' starts
#: at 2 and is 5 long, 'Fizz' starts at 9 and is 5 long, 'log' starts at 16 and is 4 long.
TEXT = 'XXfOg=rYYlrCD^ZZ#ZlHWW'

#: A function turning the decoded bytes into a string through names it reads off the global object,
#: as the one the obfuscator writes does. The evaluator does not run it, so a program holding it
#: leaves its concealed strings to the pass. Where the host has no `TextDecoder` it keeps one
#: character to a byte, unlike the obfuscator's, which decodes UTF-8 there too; Node has one.
GLOBAL_BUFFER = (
    'var __globalObject = globalThis; var __TextDecoder = __globalObject["TextDecoder"];'
    ' var __Uint8Array = __globalObject["Uint8Array"]; function bufferToString(buffer) {'
    ' if (typeof __TextDecoder !== "undefined" && __TextDecoder) {'
    ' return new __TextDecoder()["decode"](new __Uint8Array(buffer)); }'
    ' return String.fromCharCode.apply(null, buffer); }'
)

#: The long string every slicing accessor below reads, and the function turning bytes into a string.
SLICED = F'var strs = "{TEXT}";\n{GLOBAL_BUFFER}\n'

#: `ALPHABET` with `f` and `r` swapped, under which 'fOg=r' is 'nusp'.
SWAPPED = ALPHABET.translate(str.maketrans({'f': 'r', 'r': 'f'}))

#: The cache every defaulted accessor below keeps, the table it reads, and the function turning
#: bytes into a string.
DEFAULTED_HEAD = F'var cache = [], table = {TABLE};\n{GLOBAL_BUFFER}\n'


def defaulted(
    name: str,
    decode: str,
    cache: str = 'cache',
    table: str = 'table',
    order: str = 'w012345',
) -> str:
    """
    An accessor declared as *name* that keeps the decoder *decode* and the cache *cache* in two
    parameters it defaults, as the obfuscator writes it: after the two defaults, the statements
    *order* names, `w` for the branch that decodes and a digit for one of the six decoys.
    """
    decoys = [
        F'if (z == x) {{ return y[{cache}[z]] = {name}(x, y); }}',
        F'if (y) {{ [b, y] = [a(b), x || z]; return {name}(x, b, z); }}',
        F'if (z && a !== {decode}) {{ {name} = {decode}; return {name}(x, -1, z, a, b); }}',
        F'if (a === {name}) {{ {decode} = y; return {decode}(z); }}',
        F'if (a === undefined) {{ {name} = b; }}',
        F'if (z == a) {{ return y ? x[b[y]] : {cache}[x]'
        F' || (z = b[x] || a, {cache}[x] = z({table}[x])); }}',
    ]
    decodes = F'if (x !== y) {{ return b[x] || (b[x] = a({table}[x])); }}'
    body = [
        F'if (typeof a === "undefined") {{ a = {decode}; }}',
        F'if (typeof b === "undefined") {{ b = {cache}; }}',
    ]
    body.extend(decodes if key == 'w' else decoys[int(key)] for key in order)
    return F'var {name} = (x, y, z, a, b) => {{ {" ".join(body)} }};'


def slicing(name: str, decode: str, table: str = 'strs') -> str:
    """
    An accessor declared as *name* that hands *decode* the slice of *table* a call says where it
    starts and how long it is.
    """
    return F'function {name}(start, length) {{ return {decode}({table}.slice(start, start + length)); }}'


#: A slicing accessor read through a computed key.
A_SLICE_READ_THROUGH_A_COMPUTED_KEY = (
    SLICED
    + decoder('S_decode') + '\n'
    + 'function S(start, length) { return S_decode(strs["slice"](start, start + length)); }\n'
    + 'console.log(S(2, 5), S(9, 5), S(16, 4));\n'
)

#: A slicing accessor as the renaming setting leaves it: its first parameter named like itself, and
#: the locals of the decoder named like the long string.
A_SLICING_ACCESSOR_RENAMED = (
    F'var k = "{TEXT}";\n{GLOBAL_BUFFER}\n'
    + decoder('w')
    .replace('function w(str)', 'function w(w)')
    .replace('(str ||', '(w ||')
    .replace('var raw =', 'var k =')
    .replace('raw.length', 'k.length')
    .replace('raw[i]', 'k[i]')
    + '\n'
    + 'function d(d, y) { return w(k["slice"](d, d + y)); }\n'
    + 'console.log(d(2, 5), d(9, 5), d(16, 4));\n'
)

A_SLICE_PAST_THE_END_OR_OF_A_NEGATIVE_NUMBER = (
    SLICED
    + decoder('S_decode') + '\n'
    + slicing('S', 'S_decode') + '\n'
    + 'console.log(JSON.stringify([S(20, 9), S(9, -1), S(-6, 4), S(9, 5)]));\n'
)

A_SLICE_BEFORE_THE_LONG_STRING_IS_ASSIGNED = (
    F'{GLOBAL_BUFFER}\n'
    + decoder('S_decode') + '\n'
    + slicing('S', 'S_decode') + '\n'
    + 'var r;\n'
    + 'try { r = S(2, 5); } catch (e) { r = e.constructor.name; }\n'
    + F'var strs = "{TEXT}";\n'
    + 'console.log(r, S(9, 5));\n'
)

A_SLICE_IN_A_WITH_BODY = (
    SLICED
    + decoder('S_decode') + '\n'
    + slicing('S', 'S_decode') + '\n'
    + 'var o = { S: function (a, b) { return "with" + a; } };\n'
    + 'with (o) { console.log(S(2, 5)); }\n'
    + 'console.log(S(9, 5));\n'
)

#: A slicing accessor and its decoder as the moved-declaration setting hands them to a function:
#: through parameters, which a caller may fill; and beside them a slicing accessor a name holds.
A_SLICING_ACCESSOR_HELD_BY_A_PARAMETER = (
    SLICED
    + decoder('S_decode') + '\n'
    + slicing('S', 'S_decode') + '\n'
    + 'function run(a, T, T_decode) {\n'
    + F'  if (!T_decode) {{ T_decode = function (str) {{ {decoder_body()} }}; }}\n'
    + '  if (!T) { T = function (start, length) { return T_decode(strs.slice(start, start + length)); }; }\n'
    + '  return a + T(2, 5);\n'
    + '}\n'
    + 'console.log(run("x"), run("y", function (s, l) { return "own" + s; }), S(9, 5));\n'
)

#: A function shaped like the caching accessor over the long string, before and after a slicing
#: accessor over it.
A_CACHING_SHAPE_OVER_THE_LONG_STRING = tuple(
    'var cache = {};\n'
    + SLICED
    + decoder('dec') + '\n'
    + first + '\n'
    + second + '\n'
    + 'console.log(typeof acc, S(2, 5), S(9, 5), S(16, 4));\n'
    for first, second in [
        (accessor('acc', 'cache', 'dec', 'strs'), slicing('S', 'dec')),
        (slicing('S', 'dec'), accessor('acc', 'cache', 'dec', 'strs')),
    ]
)

#: A program decoding every string the long string holds, one of them twice.
A_PROGRAM_SLICING_EVERY_STRING = (
    SLICED
    + decoder('S_decode') + '\n'
    + slicing('S', 'S_decode') + '\n'
    + 'console.log(S(2, 5), S(9, 5), S(16, 4), S(2, 5));\n'
)

#: A slicing accessor spelling out the long string it slices.
A_LONG_STRING_THE_ACCESSOR_SPELLS_OUT = (
    GLOBAL_BUFFER + '\n'
    + decoder('S_decode') + '\n'
    + slicing('S', 'S_decode', F'"{TEXT}"') + '\n'
    + 'console.log(S(2, 5), S(9, 5), S(16, 4));\n'
)

#: A slicing accessor whose decoder a direct `eval` rebinds before the call. The long string is
#: short and read once, so constant inlining writes it into the accessor before the pass runs.
A_DECODER_A_DIRECT_EVAL_REBINDS = (
    SLICED
    + decoder('S_decode') + '\n'
    + slicing('S', 'S_decode') + '\n'
    + 'eval(process.argv.length > 99 ? "" : "S_decode = function (s) { return \\"evil:\\" + s; };");\n'
    + 'console.log(S(2, 5));\n'
)

#: Programs holding accessors that slice their strings out of one long string, in shapes that decide
#: what a call returns, mapped to what Node prints for each.
A_PROGRAM_SLICING_CONCEALED_STRINGS = {
    A_PROGRAM_SLICING_EVERY_STRING: 'push Fizz log push\n',
    A_LONG_STRING_THE_ACCESSOR_SPELLS_OUT: 'push Fizz log\n',
    A_DECODER_A_DIRECT_EVAL_REBINDS: 'evil:fOg=r\n',
    (
        F'var strs = "\\ud83d\\ude00{TEXT}";\n{GLOBAL_BUFFER}\n'
        + decoder('S_decode') + '\n'
        + slicing('S', 'S_decode') + '\n'
        + 'console.log(S(4, 5), S(11, 5), S(18, 4));\n'
    ): 'push Fizz log\n',
    (
        SLICED
        + decoder('S_decode') + '\n'
        + slicing('S', 'S_decode') + '\n'
        + 'console.log(S(2, 5));\n'
        + 'strs = "AAlrCD^";\n'
        + 'console.log(S(2, 5));\n'
    ): 'push\nFizz\n',
    A_SLICE_BEFORE_THE_LONG_STRING_IS_ASSIGNED: 'TypeError Fizz\n',
    A_SLICE_PAST_THE_END_OR_OF_A_NEGATIVE_NUMBER: '["l","","log","Fizz"]\n',
    (
        SLICED
        + 'function S_decode(str) { return "<" + str + ">"; }\n'
        + slicing('S', 'S_decode') + '\n'
        + 'console.log(S(2, 5));\n'
    ): '<fOg=r>\n',
    A_SLICE_IN_A_WITH_BODY: 'with2\nFizz\n',
    (
        SLICED
        + decoder('S_decode') + '\n'
        + slicing('S', 'S_decode') + '\n'
        + 'function inner() {\n'
        + '  function T_decode(str) { return "two:" + str; }\n'
        + '  ' + slicing('T', 'T_decode') + '\n'
        + '  return T(9, 5);\n'
        + '}\n'
        + 'console.log(S(2, 5), inner(), S(16, 4));\n'
    ): 'push two:lrCD^ log\n',
    A_SLICING_ACCESSOR_HELD_BY_A_PARAMETER: 'xpush yown2 Fizz\n',
    (
        SLICED
        + decoder('S_decode') + '\n'
        + slicing('S', 'S_decode') + '\n'
        + 'function inner() { return later(); }\n'
        + 'function later() { return S(9, 5); }\n'
        + 'console.log([strs].length, S(2, 5), inner());\n'
    ): '1 push Fizz\n',
    (
        SLICED
        + decoder('S_decode') + '\n'
        + slicing('S', 'S_decode') + '\n'
        + 'function inner() { return S(9, 5); }\n'
        + 'eval("strs = \\"XXlrCD^\\"");\n'
        + 'console.log(S(2, 5), inner());\n'
    ): 'Fizz \n',
    (
        SLICED
        + decoder('S_decode') + '\n'
        + slicing('S', 'S_decode') + '\n'
        + 'function inner() { return S(9, 5); }\n'
        + 'with ({}) { strs = "XXlrCD^"; }\n'
        + 'console.log(S(2, 5), inner());\n'
    ): 'Fizz \n',
    A_SLICE_READ_THROUGH_A_COMPUTED_KEY: 'push Fizz log\n',
    A_SLICING_ACCESSOR_RENAMED: 'push Fizz log\n',
    A_CACHING_SHAPE_OVER_THE_LONG_STRING[0]: 'function push Fizz log\n',
    A_CACHING_SHAPE_OVER_THE_LONG_STRING[1]: 'function push Fizz log\n',
}


AN_ACCESSOR_DECLARED_IN_A_TRY_BLOCK_INSIDE_A_LOOP = (
    HEAD
    + 'function find() {\n'
    + '  for (var k = 0; k < 2; k++) {\n'
    + '    try {\n'
    + '      ' + decoder('dec') + '\n'
    + '      ' + accessor('acc', 'cache', 'dec') + '\n'
    + '      var out = [];\n'
    + '      for (var j = 0; j < acc(10).length; j++) { out.push(j); }\n'
    + '      return acc(12) + out.length;\n'
    + '    } catch (e) {}\n'
    + '  }\n'
    + '}\n'
    + 'console.log(find());\n'
)

A_PROGRAM_FUNCTION_HOLDING_A_DECODER = (
    HEAD
    + 'function parse(src) {\n'
    + '  ' + decoder('d') + '\n'
    + '  ' + accessor('a', 'cache', 'd') + '\n'
    + '  return src + a(11);\n'
    + '}\n'
    + 'function run() {\n'
    + '  ' + decoder('parse') + '\n'
    + '  ' + accessor('acc', 'cache', 'parse') + '\n'
    + '  return acc(10);\n'
    + '}\n'
    + 'console.log(parse("x"), run());\n'
)

AN_ACCESSOR_CALLED_BEFORE_IT_IS_ASSIGNED = (
    HEAD
    + decoder('decode') + '\n'
    + 'var acc;\n'
    + 'var early;\n'
    + 'try { early = acc(10); } catch (e) { early = e.constructor.name; }\n'
    + 'acc = function (index) { ' + accessor_body('cache', 'decode') + ' };\n'
    + 'console.log(early, acc(11));\n'
)

AN_ACCESSOR_CALLED_IN_A_WITH_BODY = (
    HEAD
    + decoder('decode') + '\n'
    + accessor('acc', 'cache', 'decode') + '\n'
    + 'var o = { k: 1 };\n'
    + 'console.log(acc(10));\n'
    + 'with (o) { console.log(acc(11), k); }\n'
)

AN_ACCESSOR_IN_A_BLOCK_CALLED_INSIDE_IT_AND_AFTER_IT = (
    HEAD
    + decoder('decode') + '\n'
    + '{ ' + accessor('acc', 'cache', 'decode') + ' console.log(acc(10)); }\n'
    + 'console.log(acc(11));\n'
)

AN_ACCESSOR_IN_A_BLOCK_CALLED_ONLY_AFTER_IT = (
    HEAD
    + decoder('decode') + '\n'
    + '{ ' + accessor('acc', 'cache', 'decode') + ' }\n'
    + 'console.log(acc(11));\n'
)

A_DECODER_IN_A_BLOCK_READ_AFTER_IT = (
    HEAD
    + '{ ' + decoder('decode') + ' }\n'
    + accessor('acc', 'cache', 'decode') + '\n'
    + 'console.log(acc(10), acc(11));\n'
)

AN_ACCESSOR_IN_A_BLOCK_OF_A_FUNCTION_CALLED_AFTER_IT = (
    HEAD
    + decoder('decode') + '\n'
    + 'function main() { { ' + accessor('acc', 'cache', 'decode') + ' console.log(acc(10)); }\n'
    + 'console.log(acc(11)); }\nmain();\n'
)

AN_ACCESSOR_IN_A_BLOCK_CALLED_BEFORE_IT = (
    HEAD
    + decoder('decode') + '\n'
    + 'try { console.log(acc(11)); } catch (e) { console.log(e.constructor.name); }\n'
    + '{ ' + accessor('acc', 'cache', 'decode') + ' console.log(acc(10)); }\n'
)

#: Programs holding an accessor that defaults its decoder and its cache, with some of six decoy
#: branches before or after the one that decodes, called plainly, through `call` and `apply`, and in
#: the shapes that run a decoy or rewrite the names the decoys read, mapped to what Node prints for
#: each.
A_PROGRAM_HOLDING_A_DECOYED_ACCESSOR = {
    (
        DEFAULTED_HEAD
        + defaulted('acc', 'dec') + '\n'
        + 'console.log(acc(10), acc.call(undefined, 11), acc.apply(void 0, [12]), acc(10));\n'
        + decoder('dec') + '\n'
    ):
        'push Fizz log push\n',
    (
        DEFAULTED_HEAD
        + defaulted('acc', 'dec', order='3405w12') + '\n'
        + 'console.log(acc(10), acc(11), acc.call(void 0, 12));\n'
        + decoder('dec') + '\n'
    ):
        'push Fizz log\n',
    (
        DEFAULTED_HEAD
        + defaulted('acc', 'dec', order='1w') + '\n'
        + 'var r;\n'
        + 'try { r = acc(10, 10); } catch (e) { r = e.constructor.name; }\n'
        + 'console.log(typeof r, acc(11));\n'
        + decoder('dec') + '\n'
    ):
        'string Fizz\n',
    (
        DEFAULTED_HEAD
        + defaulted('acc', 'dec', order='4w') + '\n'
        + 'console.log(acc.call({}, 10), acc(11));\n'
        + decoder('dec') + '\n'
    ):
        'push Fizz\n',
    (
        DEFAULTED_HEAD
        + defaulted('acc', 'dec', order='w0') + '\n'
        + 'var k = 10;\n'
        + 'console.log(acc(k), acc(11));\n'
        + decoder('dec') + '\n'
    ):
        'push Fizz\n',
    (
        DEFAULTED_HEAD
        + defaulted('acc', 'dec', order='1w') + '\n'
        + 'var r;\n'
        + 'try { r = [10, 11].map(acc).join(); } catch (e) { r = e.constructor.name; }\n'
        + 'console.log(r, acc(12));\n'
        + decoder('dec') + '\n'
    ):
        'RangeError log\n',
    (
        DEFAULTED_HEAD
        + defaulted('acc', 'dec', order='3w') + '\n'
        + 'console.log(acc(10));\n'
        + 'dec = function (s) { return "X" + s; };\n'
        + 'console.log(acc(11));\n'
        + decoder('dec') + '\n'
    ):
        'push\nXlrCD^\n',
    (
        DEFAULTED_HEAD
        + defaulted('acc', 'dec', order='2w') + '\n'
        + 'console.log(acc(10));\n'
        + 'acc = function (i) { return "X" + i; };\n'
        + 'console.log(acc(11));\n'
        + decoder('dec') + '\n'
    ):
        'push\nX11\n',
    (
        DEFAULTED_HEAD
        + defaulted('acc', 'dec', order='4w') + '\n'
        + 'var r;\n'
        + 'try { r = acc(10); } catch (e) { r = e.constructor.name; }\n'
        + 'console.log(r, typeof acc);\n'
        + '{ ' + decoder('dec') + ' }\n'
    ):
        'TypeError object\n',
    (
        GLOBAL_BUFFER + '\n'
        + 'function run() {\n'
        + F'  var cache = [], table = {TABLE};\n'
        + '  var undefined = dec;\n'
        + '  ' + defaulted('acc', 'dec', order='4w') + '\n'
        + '  var r;\n'
        + '  try { r = acc(10); } catch (e) { r = e.constructor.name; }\n'
        + '  return r + " " + typeof acc;\n'
        + '  ' + decoder('dec') + '\n'
        + '}\n'
        + 'console.log(run());\n'
    ):
        'push object\n',
    (
        DEFAULTED_HEAD
        + defaulted('acc', 'dec', order='w5') + '\n'
        + 'var o = { acc: function (i) { return "with" + i; } };\n'
        + 'with (o) { console.log(acc(10)); }\n'
        + 'console.log(acc(11));\n'
        + decoder('dec') + '\n'
    ):
        'with10\nFizz\n',
    (
        DEFAULTED_HEAD
        + defaulted('acc', 'dec', order='w0') + '\n'
        + 'var r;\n'
        + 'try { r = new acc(10); } catch (e) { r = e.constructor.name; }\n'
        + 'console.log(r, acc(11));\n'
        + decoder('dec') + '\n'
    ):
        'TypeError Fizz\n',
    (
        DEFAULTED_HEAD
        + defaulted('acc', 'dec', order='0w3') + '\n'
        + 'function inner() {\n'
        + '  ' + defaulted('acc2', 'dec2', order='w45') + '\n'
        + '  return acc2(12);\n'
        + '  ' + decoder('dec2') + '\n'
        + '}\n'
        + 'console.log(acc(10), acc(11), inner(), acc(10));\n'
        + decoder('dec') + '\n'
    ):
        'push Fizz log push\n',
    (
        DEFAULTED_HEAD
        + 'function run(flag) {\n'
        + '  if (flag) {\n'
        + '    ' + defaulted('acc', 'dec', order='5w1') + '\n'
        + '    var out = acc(10) + acc.apply(undefined, [11]);\n'
        + '    console.log(out);\n'
        + '    ' + decoder('dec') + '\n'
        + '  }\n'
        + '}\n'
        + 'run(true);\n'
    ):
        'pushFizz\n',
    (
        DEFAULTED_HEAD
        + 'function run() {\n'
        + '  for (const k of [10, 11]) {\n'
        + '    ' + defaulted('acc', 'dec', order='w2') + '\n'
        + '    console.log(acc(10), acc(12));\n'
        + '    ' + decoder('dec') + '\n'
        + '  }\n'
        + '}\n'
        + 'run();\n'
    ):
        'push log\npush log\n',
    (
        DEFAULTED_HEAD
        + defaulted('acc', 'dec', order='01w') + '\n'
        + 'console.log(typeof acc);\n'
        + decoder('dec') + '\n'
    ):
        'function\n',
    (
        DEFAULTED_HEAD
        + defaulted('acc', 'dec', order='w0') + '\n'
        + 'var original = Function.prototype.call;\n'
        + 'Function.prototype.call = function (receiver, index) { return "called" + index; };\n'
        + 'var r = acc.call(undefined, 10);\n'
        + 'Function.prototype.call = original;\n'
        + 'console.log(r, acc(11));\n'
        + decoder('dec') + '\n'
    ):
        'called10 Fizz\n',
    (
        DEFAULTED_HEAD
        + 'var r;\n'
        + 'try { r = acc(10); } catch (e) { r = e.constructor.name; }\n'
        + defaulted('acc', 'dec', order='4w') + '\n'
        + 'console.log(r, acc(11));\n'
        + decoder('dec') + '\n'
    ):
        'TypeError Fizz\n',
    (
        'var cache = [], table;\n'
        + GLOBAL_BUFFER + '\n'
        + defaulted('acc', 'dec', order='w4') + '\n'
        + 'var r;\n'
        + 'try { r = acc(10); } catch (e) { r = e.constructor.name; }\n'
        + F'table = {TABLE};\n'
        + 'console.log(r, acc(11));\n'
        + decoder('dec') + '\n'
    ):
        'TypeError Fizz\n',
    (
        DEFAULTED_HEAD
        + defaulted('acc', 'dec', order='w') + '\n'
        + 'console.log(acc(10), acc(11), acc(12), acc(10));\n'
        + decoder('dec') + '\n'
    ):
        'push Fizz log push\n',
    (
        DEFAULTED_HEAD
        + defaulted('acc', 'dec', order='w') + '\n'
        + 'console.log(acc(10, undefined, undefined, function (s) { return "own"; }),'
        + ' acc(10), acc(11));\n'
        + decoder('dec') + '\n'
    ):
        'own own Fizz\n',
    (
        DEFAULTED_HEAD
        + defaulted('acc', 'dec', order='w') + '\n'
        + 'cache[10] = "planted";\n'
        + 'console.log(acc(10), acc(11));\n'
        + decoder('dec') + '\n'
    ):
        'planted Fizz\n',
    (
        DEFAULTED_HEAD
        + defaulted('acc', 'dec', order='w') + '\n'
        + 'console.log(acc(...[10]), acc(11));\n'
        + decoder('dec') + '\n'
    ):
        'push Fizz\n',
    (
        DEFAULTED_HEAD
        + defaulted('acc', 'dec', order='w') + '\n'
        + 'function fill(c) { c[11] = "filled"; }\n'
        + 'fill(cache);\n'
        + 'console.log(acc(10), acc(11));\n'
        + decoder('dec') + '\n'
    ):
        'push filled\n',
    (
        F'{GLOBAL_BUFFER}\n'
        F'var cache = [], table = {TABLE}, get = (x, y, z, a, b) => {{'
        ' if (typeof a === "undefined") { a = dec; } if (typeof b === "undefined") { b = cache; }'
        ' if (x !== y) { return b[x] || (b[x] = a(table[x])); }'
        ' if (a === void 0) { get = b; }'
        ' if (z == x) { return y[cache[z]] = get(x, y); } };\n'
        F'{decoder("dec")}\n'
        'console.log(get(11), get.call(void 0, 12), get.apply(void 0, [10]));'
    ):
        'Fizz log push\n',
    (
        F'{DEFAULTED_HEAD}{decoder("dec")}\n'
        F'{defaulted("get", "dec", order="3w1")}\n'
        'console.log(get(0xb), get.call(undefined, 0xc));'
    ):
        'Fizz log\n',
    (
        F'{DEFAULTED_HEAD}'
        'function f(k) {\n'
        '  switch (k) {\n'
        '    case 1:\n'
        F'      {defaulted("get", "dec", order="0w2")}\n'
        '      console.log(get(11));\n'
        F'      {decoder("dec")}\n'
        '      break;\n'
        '  }\n'
        '}\n'
        'f(1);'
    ):
        'Fizz\n',
    (
        F'{DEFAULTED_HEAD}'
        'function f() {\n'
        '  var keep;\n'
        '  {\n'
        F'    {defaulted("get", "dec", order="w5")}\n'
        '    keep = function () { return get(11); };\n'
        F'    {decoder("dec")}\n'
        '  }\n'
        '  return keep();\n'
        '}\n'
        'console.log(f());'
    ):
        'Fizz\n',
    (
        '"use strict";\n'
        F'{DEFAULTED_HEAD}'
        'function f() {\n'
        '  {\n'
        F'    {defaulted("get", "dec", order="1w")}\n'
        '    console.log(get(12));\n'
        F'    {decoder("dec")}\n'
        '  }\n'
        '}\n'
        'f();'
    ):
        'log\n',
    (
        F'{DEFAULTED_HEAD}'
        'function f() {\n'
        '  {\n'
        F'    {defaulted("get", "dec", order="w")}\n'
        '    console.log(get(11));\n'
        F'    {decoder("dec")}\n'
        '  }\n'
        F'  {defaulted("other", "dec", order="w0")}\n'
        '  console.log(other(12));\n'
        '}\n'
        'f();'
    ):
        'Fizz\nlog\n',
    (
        F'{DEFAULTED_HEAD}'
        'function f() {\n'
        F'  {defaulted("other", "dec", order="w0")}\n'
        '  try { console.log(other(12)); } catch (e) { console.log(e.constructor.name); }\n'
        '  {\n'
        F'    {defaulted("get", "dec", order="w")}\n'
        '    console.log(get(11));\n'
        F'    {decoder("dec")}\n'
        '  }\n'
        '}\n'
        'f();'
    ):
        'TypeError\nFizz\n',
    (
        F'{DEFAULTED_HEAD}'
        'function f() {\n'
        '  {\n'
        F'    {defaulted("get", "dec", order="w")}\n'
        '    console.log(get(11));\n'
        F'    {decoder("dec")}\n'
        '  }\n'
        '  {\n'
        F'    {defaulted("got", "dec", order="w4")}\n'
        '    console.log(got(12));\n'
        F'    {decoder("dec", SWAPPED)}\n'
        '  }\n'
        '}\n'
        'f();'
    ):
        'Fizz\nlog\n',
    (
        DEFAULTED_HEAD
        + 'var r = acc?.call(undefined, 10);\n'
        + defaulted('acc', 'dec', order='3w1') + '\n'
        + 'console.log(r, acc(11));\n'
        + decoder('dec') + '\n'
    ):
        'undefined Fizz\n',
    (
        DEFAULTED_HEAD
        + 'var r; try { r = acc.call?.(undefined, 10); } catch (e) { r = e.constructor.name; }\n'
        + defaulted('acc', 'dec', order='3w1') + '\n'
        + 'console.log(r, acc(11));\n'
        + decoder('dec') + '\n'
    ):
        'TypeError Fizz\n',
    (
        DEFAULTED_HEAD
        + defaulted('acc', 'dec', order='w1') + '\n'
        + 'console.log(acc.apply(undefined, [10]), acc(11));\n'
        + decoder('dec') + '\n'
    ):
        'push Fizz\n',
    (
        DEFAULTED_HEAD
        + defaulted('acc', 'dec', order='w1') + '\n'
        + 'var n = 0;\n'
        + 'console.log(acc.call(void n++, 10), n);\n'
        + decoder('dec') + '\n'
    ):
        'push 1\n',
    (
        DEFAULTED_HEAD
        + 'function f() {\n'
        + '  var r; try { r = get(11); } catch (e) { r = e.constructor.name; }\n'
        + '  {\n'
        + '    ' + defaulted('get', 'dec', order='1w4') + '\n'
        + '    r += "," + get(12);\n'
        + '    ' + decoder('dec') + '\n'
        + '  }\n'
        + '  return r;\n'
        + '}\n'
        + 'console.log(f());\n'
    ):
        'TypeError,log\n',
    (
        DEFAULTED_HEAD
        + 'function f() {\n'
        + '  var set;\n'
        + '  {\n'
        + '    set = function () { dec = function (s) { return "X"; }; };\n'
        + '    ' + defaulted('get', 'dec', order='w') + '\n'
        + '    set();\n'
        + '    var r = get(11);\n'
        + '    ' + decoder('dec') + '\n'
        + '  }\n'
        + '  return r;\n'
        + '}\n'
        + 'console.log(f());\n'
    ):
        'X\n',
    (
        DEFAULTED_HEAD
        + 'function f() {\n'
        + '  {\n'
        + '    ' + defaulted('get', 'dec', order='w2') + '\n'
        + '    ' + decoder('dec') + '\n'
        + '  }\n'
        + '  dec = undefined;\n'
        + '  return get(11);\n'
        + '}\n'
        + 'console.log(f());\n'
    ):
        'Fizz\n',
}

#: A classic script calling its decoyed accessor through the global object with two arguments, which
#: runs a decoy, mapped to what a host prints for it.
A_SCRIPT_CALLING_A_DECOYED_ACCESSOR_THROUGH_THE_GLOBAL_OBJECT = {
    (
        DEFAULTED_HEAD
        + defaulted('acc', 'dec', order='1w') + '\n'
        + 'var r; try { r = globalThis.acc(10, 10); } catch (e) { r = e.constructor.name; }\n'
        + 'console.log(typeof r, acc(11));\n'
        + decoder('dec') + '\n'
    ):
        'string Fizz\n',
}

#: Programs holding the machinery of concealed strings in a shape that decides what a call of an
#: accessor returns or whether the machinery is still named, mapped to what Node prints for each.
A_PROGRAM_HOLDING_CONCEALED_STRINGS = {
    AN_ACCESSOR_DECLARED_IN_A_TRY_BLOCK_INSIDE_A_LOOP: 'log4\n',
    AN_ACCESSOR_IN_A_BLOCK_CALLED_INSIDE_IT_AND_AFTER_IT: 'push\nFizz\n',
    AN_ACCESSOR_IN_A_BLOCK_CALLED_ONLY_AFTER_IT: 'Fizz\n',
    A_DECODER_IN_A_BLOCK_READ_AFTER_IT: 'push Fizz\n',
    AN_ACCESSOR_IN_A_BLOCK_OF_A_FUNCTION_CALLED_AFTER_IT: 'push\nFizz\n',
    AN_ACCESSOR_IN_A_BLOCK_CALLED_BEFORE_IT: 'TypeError\npush\n',
    A_PROGRAM_FUNCTION_HOLDING_A_DECODER: 'xFizz push\n',
    AN_ACCESSOR_CALLED_BEFORE_IT_IS_ASSIGNED: 'TypeError Fizz\n',
    AN_ACCESSOR_CALLED_IN_A_WITH_BODY: 'push\nFizz 1\n',
    (
        HEAD
        + 'function g() {\n'
        + '  ' + decoder('D') + '\n'
        + '  ' + accessor('A', 'cache', 'D') + '\n'
        + '  return A(10);\n'
        + '}\n'
        + 'function f(a, D, A) {\n'
        + '  if (!A) { A = function (index) { ' + accessor_body('cache', 'D') + ' }; }\n'
        + '  if (!D) { D = function (str) { ' + decoder_body() + ' }; }\n'
        + '  return a + A(11);\n'
        + '}\n'
        + 'console.log(g(), f("x"));\n'
    ): 'push xFizz\n',
    (
        HEAD
        + decoder('decode') + '\n'
        + accessor('acc', 'cache', 'decode') + '\n'
        + 'console.log(typeof new acc(10), acc(11));\n'
    ): 'object Fizz\n',
    (
        F'var NS = {{}};\nNS.cache = {{}};\n{BUFFER}\n'
        + decoder('decode') + '\n'
        + accessor('acc', 'NS.cache', 'decode', 'NS.table') + '\n'
        + 'var early;\n'
        + 'try { early = acc(10); } catch (e) { early = e.constructor.name; }\n'
        + F'NS.table = {TABLE};\n'
        + 'console.log(early, acc(11));\n'
    ): 'TypeError Fizz\n',
    (
        F'var NS = {{}};\nNS.cache = {{}};\n{BUFFER}\n'
        + F'NS.table = {TABLE};\n'
        + decoder('decode') + '\n'
        + accessor('acc', 'NS.cache', 'decode', 'NS.table') + '\n'
        + 'NS.table = ["a","b","c","d","e","f","g","h","i","j","#ZlH","#ZlH","fOg=r"];\n'
        + 'console.log(acc(10), acc(12));\n'
    ): 'log push\n',
    (
        HEAD
        + decoder('decode') + '\n'
        + accessor('acc', 'cache', 'decode') + '\n'
        + 'console.log(acc(10), decode("lrCD^"));\n'
    ): 'push Fizz\n',
    (
        HEAD
        + decoder('decode') + '\n'
        + 'var acc = function (index) { ' + accessor_body('cache', 'decode') + ' };\n'
        + 'var first = acc(10);\n'
        + 'acc = function () { return "other"; };\n'
        + 'console.log(first, acc(11));\n'
    ): 'push other\n',
    (
        HEAD
        + 'function run(o) {\n'
        + '  ' + decoder('decode') + '\n'
        + '  ' + accessor('acc', 'cache', 'decode') + '\n'
        + '  var a = acc(10);\n'
        + '  with (o) { return a + acc(11) + k; }\n'
        + '}\n'
        + 'console.log(run({ k: 1 }));\n'
    ): 'pushFizz1\n',
    (
        HEAD
        + decoder('decode') + '\n'
        + accessor('acc', 'cache', 'decode') + '\n'
        + 'console.log(acc(10));\n'
        + 'function later(o) {\n'
        + '  with (o) {\n'
        + '    acc2 = function (index) { ' + accessor_body('cache', 'decode') + ' };\n'
        + '    return acc2(11);\n'
        + '  }\n'
        + '}\n'
        + 'var acc2;\n'
        + 'console.log(later({}));\n'
    ): 'push\nFizz\n',
    (
        HEAD
        + decoder('decode') + '\n'
        + accessor('acc', 'cache', 'decode') + '\n'
        + 'console.log(acc(10));\n'
        + 'var o = { k: 1 };\n'
        + 'with (o) {\n'
        + '  ' + decoder('decode2') + '\n'
        + '  ' + accessor('acc2', 'cache', 'decode2') + '\n'
        + '  console.log(acc2(11), k);\n'
        + '}\n'
    ): 'push\nFizz 1\n',
    (
        F'var cache = {{}};\nvar table = {TABLE_WITH_A_BYTE_ORDER_MARK};\n{TEXT_DECODER}\n'
        + decoder('decode') + '\n'
        + accessor('acc', 'cache', 'decode') + '\n'
        + 'console.log(JSON.stringify(acc(11)), acc(11).length);\n'
    ): '"Fizz" 4\n',
    (
        HEAD
        + decoder('decode') + '\n'
        + accessor('acc', 'cache', 'decode') + '\n'
        + F'eval(Date.now() > 0 ? "table = " + JSON.stringify({OTHER_TABLE}) : "");\n'
        + 'console.log(acc(10));\n'
    ): 'Fizz\n',
    (
        F'var cache = {{}};\nvar table = {TABLE_WITH_AN_ASTRAL_CHARACTER};\n{BUFFER}\n'
        + decoder('decode') + '\n'
        + accessor('acc', 'cache', 'decode') + '\n'
        + 'var s = acc(0);\n'
        + 'console.log(s.length, s.charCodeAt(0), s.charCodeAt(1), s.split("").length);\n'
    ): '2 55357 56832 2\n',
    (
        HEAD
        + decoder('decode') + '\n'
        + 'function acc(index) { if (typeof cache[index] === "undefined") { '
        + 'return cache[index] = decode(table[index]).split("").reverse().join(""); } return cache[index]; }\n'
        + 'console.log(acc(10), acc(11));\n'
    ): 'hsup zziF\n',
    (
        F'var table = {TABLE};\n{BUFFER}\n'
        + decoder('decode') + '\n'
        + accessor('acc', 'cache', 'decode') + '\n'
        + 'var early;\n'
        + 'try { early = acc(10); } catch (e) { early = e.constructor.name; }\n'
        + 'var cache = {};\n'
        + 'console.log(early, acc(11));\n'
    ): 'TypeError Fizz\n',
    (
        F'var NS = {{}};\nNS.cache = {{}};\n{BUFFER}\n'
        + F'NS.table = {TABLE};\n'
        + decoder('decode') + '\n'
        + accessor('acc', 'NS.cache', 'decode', 'NS.table') + '\n'
        + 'function swap(o) { with (o) { NS.table = ["a","b","c","d","e","f","g","h","i","j","#ZlH","#ZlH","fOg=r"]; } }\n'
        + 'swap({});\n'
        + 'console.log(acc(10), acc(12));\n'
    ): 'log push\n',
    (
        'var memo = {};\n'
        'var words = ["red","green","blue","cyan","magenta","yellow","black","white","gray","pink","alpha","six","abc"];\n'
        'function encode(str) { var table = "' + ALPHABET.replace('"', '\\"') + '"; '
        'var raw = Buffer.from(str, "utf-8"); var len = raw.length; var ret = ""; var n = 0; var b = 0; '
        'for (var i = 0; i < len; i++) { b |= raw[i] << n; n += 8; if (n > 13) { var v = b & 8191; '
        'if (v > 88) { b >>= 13; n -= 13; } else { v = b & 16383; b >>= 14; n -= 14; } '
        'ret += table[v % 91] + table[(v / 91) | 0]; } } '
        'if (n) { ret += table[b % 91]; if (n > 7 || b > 90) ret += table[(b / 91) | 0]; } return ret; }\n'
        'function encoded(index) { if (typeof memo[index] === "undefined") { return memo[index] = encode(words[index]); } '
        'return memo[index]; }\n'
        'console.log(encoded(10), encoded(12));\n'
    ): 'S?aHNE0 pQ*l\n',
    (
        HEAD
        + decoder('decode') + '\n'
        + accessor('acc', 'cache', 'decode') + '\n'
        + accessor('acc2', 'cache', 'decode') + '\n'
        + 'console.log(acc(10));\n'
        + 'with ({}) { console.log(acc2(11)); }\n'
    ): 'push\nFizz\n',
    (
        F'var NS = {{}};\nNS.cache = {{}};\nNS.table = {TABLE};\n'
        + F'NS.swap = function () {{ this.table = {OTHER_TABLE}; }};\n'
        + BUFFER + '\n'
        + decoder('decode') + '\n'
        + accessor('acc', 'NS.cache', 'decode', 'NS.table') + '\n'
        + 'NS.swap();\n'
        + 'console.log(acc(10));\n'
    ): 'Fizz\n',
    (
        F'var other = {OTHER_TABLE};\n'
        + 'var NS = { cache: {}, get table() { return other; }, set table(v) {} };\n'
        + F'NS.table = {TABLE};\n'
        + BUFFER + '\n'
        + decoder('decode') + '\n'
        + accessor('acc', 'NS.cache', 'decode', 'NS.table') + '\n'
        + 'console.log(acc(10));\n'
    ): 'Fizz\n',
    (
        HEAD
        + decoder('decode') + '\n'
        + accessor('acc', 'cache', 'decode') + '\n'
        + 'table[10] = "lrCD^";\n'
        + 'console.log(acc(10));\n'
    ): 'Fizz\n',
    (
        HEAD
        + decoder('decode') + '\n'
        + accessor('acc', 'cache', 'decode') + '\n'
        + 'table.reverse();\n'
        + 'console.log(acc(0));\n'
    ): 'log\n',
    (
        HEAD
        + decoder('decode') + '\n'
        + accessor('acc', 'cache', 'decode') + '\n'
        + 'cache[10] = "other";\n'
        + 'console.log(acc(10));\n'
    ): 'other\n',
}


class TestStringConcealing(TestJsDeobfuscator):

    @staticmethod
    def _decode_js(name: str, alphabet: str, indent: int = 4) -> list[str]:
        p = ' ' * indent
        return [
            F'function {name}(str) {{',
            F'{p}var alpha = "{alphabet}";',
            F'{p}var raw = "" + (str || "");',
            F'{p}var len = raw.length;',
            F'{p}var ret = [];',
            F'{p}var b = 0, n = 0, v = -1;',
            F'{p}for (var i = 0; i < len; i++) {{',
            F'{p}    var p = alpha.indexOf(raw[i]);',
            F'{p}    if (p === -1) continue;',
            F'{p}    if (v < 0) {{ v = p; }}',
            F'{p}    else {{',
            F'{p}        v += p * 91;',
            F'{p}        b |= v << n;',
            F'{p}        n += (v & 8191) > 88 ? 13 : 14;',
            F'{p}        do {{ ret.push(b & 0xff); b >>= 8; n -= 8; }} while (n > 7);',
            F'{p}        v = -1;',
            F'{p}    }}',
            F'{p}}}',
            F'{p}if (v > -1) {{ ret.push((b | v << n) & 0xff); }}',
            F'{p}return bufferToString(ret);',
            '}',
        ]

    @staticmethod
    def _access_js(
        name: str,
        cache: str,
        decoder: str,
        table: str = 'table',
        indent: int = 4,
    ) -> list[str]:
        p = ' ' * indent
        q = "'" if indent == 4 else '"'
        return [
            F'function {name}(index) {{',
            F'{p}if (typeof {cache}[index] === {q}undefined{q}) {{',
            F'{p}    return {cache}[index] = {decoder}({table}[index]);',
            F'{p}}}',
            F'{p}return {cache}[index];',
            '}',
        ]

    _ESCAPED_ALPHABET = ALPHABET.replace('"', '\\"')

    def _minimal_sample(self) -> str:
        return '\n'.join([
            'var cache = {};',
            'var table = ["aa","bb","cc","dd","ee","ff","gg","hh","ii","jj",'
            '"fOg=r","lrCD^","#ZlH"];',
            *self._decode_js('decode', self._ESCAPED_ALPHABET),
            *self._access_js('accessor', 'cache', 'decode'),
            'var results = [];',
            'results[accessor(10)]("hello");',
            'console[accessor(12)](results);',
        ])

    def test_base91_decode(self):
        self.assertEqual(_decode_base91('fOg=r', ALPHABET), 'push')
        self.assertEqual(_decode_base91('lrCD^', ALPHABET), 'Fizz')
        self.assertEqual(_decode_base91('#ZlH', ALPHABET), 'log')

    def test_base91_decodes_a_character_above_the_basic_plane_to_its_two_code_units(self):
        self.assertEqual(_decode_base91('{<@g2', ALPHABET), '\ud83d\ude00')

    def test_accessor_calls_resolved(self):
        result = self._deobfuscate(self._minimal_sample())
        self.assertEqual(
            inspect.cleandoc(
                """
                var results = [];
                results.push("hello");
                console.log(results);
                """
            ),
            result,
        )

    def test_accessor_kept_until_inlined_argument_resolves(self):
        source = '\n'.join([
            'var cache = {};',
            'var table = ["aa","bb","cc","dd","ee","ff","gg","hh","ii","jj",'
            '"fOg=r","lrCD^","#ZlH"];',
            *self._decode_js('decode', self._ESCAPED_ALPHABET),
            *self._access_js('accessor', 'cache', 'decode'),
            'var k = 10;',
            'var results = [];',
            'results[accessor(k)]("hello");',
            'console[accessor(12)](results);',
        ])
        self.assertEqual(
            inspect.cleandoc(
                """
                var results = [];
                results.push("hello");
                console.log(results);
                """
            ),
            self._deobfuscate(source),
        )

    def test_accessor_recognizable_once_its_unused_declarations_are_removed_is_resolved(self):
        """
        The accessor declares two variables it never uses, so it has four statements and does not
        match the accessor pattern until unused-code removal drops them. That removal runs after
        string decoding, and a change in any group runs string decoding again.
        """
        accessor = self._access_js('accessor', 'cache', 'decode')
        accessor[1:1] = ['    var unused;', '    var other;']
        source = '\n'.join([
            'var cache = {};',
            'var table = ["aa","bb","cc","dd","ee","ff","gg","hh","ii","jj",'
            '"fOg=r","lrCD^","#ZlH"];',
            *self._decode_js('decode', self._ESCAPED_ALPHABET),
            *accessor,
            'var results = [];',
            'results[accessor(10)]("hello");',
            'console[accessor(12)](results);',
        ])
        self.assertEqual(
            inspect.cleandoc(
                """
                var results = [];
                results.push("hello");
                console.log(results);
                """
            ),
            self._deobfuscate(source),
        )

    def test_full_fizzbuzz_sample(self):
        """
        The whole recovered program is a single `console.log` of the FizzBuzz array; the dead
        global-object helper preamble the string-concealing sample carries is fully removed.
        """
        source = lzma.decompress(base64.b85decode(
            "{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;3H2DoLvAj9ZCPGVfzyXn;9}d7=bd;P-u|=hS4y!t6q`3iYd7Jn@gb<iH1XeW)Th&veG?%"
            "YwBK2@+d2^J$YeG%M4UKdAGD!4GsZVt`^bppHR_iV0FXK*h#6x)K@pE_d426aHY}ck*@-Z<qci=bK`7R;<|B{jy#q`0RF-r89E<6"
            "0NR8U5LQ4+SMYp0!@U)YE9aZ2<C1H(i)Ja=td{a`jBi3Pw2b`|RxTgt!Zt?T5A+=vwd3}<`A_)<#%0j}rE<Uyze9OMpIYM_yB$8f"
            "lFYLgihO@M;R;Yy*bT@NU~MBn!72xabk|YC97+%~)WLf?Y31`n`4ox#nBkldkM-DO_pL|x_|x!m_#cR+AoS4U(gq!N;y|W&li7Dr"
            "nYt}Xh@0~yU}Ie{%l!DLhXZjK38YEcGr#;06*+dTW*|Z4IzC30a<XYwiSyWmZ}o_yAuFJtrYSq`eeQ43_^zW{lURqRypcD{vD6vs"
            "ZgMB2f5zJhsbiAW`Y#5wMJTkZM>0fs6cOIh^{+7~Ig)3?Djuny%SQBcKsJRv=F7ruU2*G%D#|>zbUHn>Urfsomq_Ow_7nSzY+=QJ"
            "qKGT85z=|d<@mT@WM7Atb3#%oC0z()pmE1X)6i)v^dc4Ul?qPRc8U#lYArH4)y0K*XCKu;;p_0(4S#^zKK$Y@;IeB{ZJpIu(~!;W"
            "8<!)^wVux4hdJf(L_xS$salx~v4bQa(3!!Xy7(&+L-5#k7ikmuP?%8^UQ*yW<nGbs!VC3r>r(wyrB8qJ{Ls2Y6p9Ne%sujz-usGQ"
            "SK`pcyy5RsI;t>-f!$B=F7J#rnKYIh1w+T@kkEH_0*gleI<#_B7||ICyQ=*v580&)bSy0xY@cTsg1Eu1=hVH|U8c6G+-#JiKvY*m"
            "#%7EGFYA~v_;R^tyZ43gYt7<l0t^U7;z)BT6Qq7eMO-NLyn-toN#j%~F23{p40Q$ppFVcrV1feuAN&I=5KB7GF;N3;{mcZHyDdM2"
            "24j$QODP9r|0ic>%L6`AC^ca^_ZQl)Th04=QV>#g4Cu>+P9L?fSp@$hP<eR}RzF|DxYkyb53yuALn<zvvnj5)TbLyz0}F)qH`!@5"
            "L;hN8?f<4@5sx2SSR@zz7L5fTHT!d(p<FLE=*EUw3z-~=H;L&9tqqrZUsZ1O0EfjhA#VWv6@%<<4q%diHkFJRf%U$z2&Yd2wx~}N"
            "8GKlrJ#x1trcK?{NLZ0A0B1TMN6Bk<W3nGrVQT^LI!^)figyO`8+$zJTU!;hd+K;G|1j?R1N8TI4R}vUzL;{_?g_gZacLo_LUM}<"
            "e`RZmxr?u2wsxBptfS5+O+d5;24<1Gv@0?G|3etT#Ww*ks)etI@<$>$Yqw@i9uQY(AY*3W{yRsW4(nMlXKV>i#8_&Ipg8z%o&FZg"
            "nOAfqHNKzTjXbyciwn7sv|i`<r*uv+dgSod5T-hS7*`d2bzXuEF*Ft^1Frk%^HOVh{yusXFXIoZz<Nset6Iyv<K@pR-!Q$&x$kfS"
            "W!Pm^N+dZa^F))r`If9OV>mtcY5WIxKo*R*=E3`#PJ9EL&&6UT7hxR`$XWdc@Ewd2U(xpH<Os^P=<}aa+;Z8H5{B6?&9gC-80`sV"
            "ISjF44et8`pYu>m*(C(A9k`T<O9rQ@7i$=lY=OE^WfCk-)JKEcUn3h+v-|GbcA7a;CWHsB$6eh#o`eY}wl5cja*f|l4)WHRT9`d_"
            "2`gyKRbWSEvL5I!CE?yx?P$n0JbjEfK4lt_<WUW!0mP>*WZy<vF;*zH2MQBr?FSx>S8pMts~UH*f$G+f66qzov+O(Hfp<)TRlz3f"
            "+%K8ebvZ>bNk(tU7f^nW<`xg7HyvS6?jU#a&ZzOrw`FT2)Og@RAy6UO9f+2DpF~6c8Pmf`Ko%a#>15r%4vxTQ_j5G?oFL2n#R1Ua"
            "JWaG+-Q5@^)e;rae;3~G623vIL(=(6ITQuGl;SKodlc_WV}2f(zF>M#_ZlbwEcnwcU~C*$LeJe=*Ni#2l-T^#;I3v5$5};p1Ah=i"
            "tTuAI+&Jjv@ia5(TZsg~6p(dNrLq!h;Y}g-txi}K2mrVZpfUN!UB!J1fW64J>;&gWXo^S;0|2bt2KJc1WMz8q5QNFoEFhYEZSZNx"
            "6HP&s%<fjD^mV5;xOlOgXC`Tn{?#WJvcUvx@ODT+6q)|&@5F&Ya7t>4Y98xnquQe?nd%?lAiiTehcq5A`6O+5w<17tXm6?3k?+i9"
            "G^1advdX4vJ_+s+L2n0n98k@`EW;~(LlSc!Ac}!u64*|C$brcSR|EX@AEk?I?|*(d-2CHZTd<%4U^uq0p{4uZ_9luHcvIpsoJcys"
            "ll{2_al}beNxRr#v*AoDi)SyZVZ}9JgADq^zA$wh+fSOSiPzJF7XS#nZdLXGW#9vR8<d_`_no8nS$Oqeii%>u6$crna8nv9Is;)0"
            "!0<<$?wjkivufO0P5PVwY9nv(oV&7BaUeXk1HY!`uTAiMQ$m=z09cdwbsk^4en8P0i>y`^LS7AXzMZ0=J|c;=36@kEG_XYS4+A<P"
            "ww5j5YLdZ3ZO#E%2OU&N{)CJl<|efQTPn-ZOsG)I$t<-Dv0{)0{!jZB%s4z}-Y|BEFFK&T?SEan;gZZamc&<8-Eq%V%2P}3dBmYc"
            "^yMOS(6p7xu+k!t16w@H>;?jX{WJ|v>qS1y{YbbFl_<<;`=!HHJXduBFRd8-G~=5G<2H*C-$fZ4mqBu4>YOWvzbfS=l&i64`07Qt"
            "QKmyegh4)u2lLW@>!-bM3Nh?4RiiqrmInTCMXWxJk25%ABW>H4tVQ+H3%-;_2=ds>=&DwZl#7}&yHPZRoo=q&*89ut<GlJQ5uesi"
            "!tapVwZ&^nz>Z@*$gaB~FgbV?6J8!&d+(p8(}2q}ccMkaX$5lokEWlWPf$EWT@>OUqPR!2mOGB6!?o#V&(`Y>5QkDBQFTf~Dk|Ns"
            "G$dD3{**Ri^B?9Rm0x<lW#9!cY>=Z4S;QVg4_MJKYDfz^Tx9Clhibw7{sEDYfNkw%w&>C)aKqF&JG+C)mo014pvMD|Y94)SFcg+s"
            "m`mddGz*<{&b3qmCnYed_ZB6UaV=llt|U}6e4I)B8)hK7%0@b%Ld`eS%_3{DU<#!Mk4s&@wHB0t+AB}a;UyAFm)gZ*o6|N0fsc6i"
            "5j3&3a(pklsrt<se!<N37tDXfEcjicg3QCahc^g6WpU<OAugoO^|p(vL*)tk&a(NNe%Z(R)$Rv9Ox0D9aVBL%V6)pRN23qOd=+4U"
            "r8eCWH6GiSpoTN((IV$}_N?el9<+iJ<4T*lZWvh5J9I$7jd`>2xLRua!FtW_b8-}XrDfG?%FJlTpYnvRA((&zmsD{}h1BZCqAj3K"
            "-%|W;7qO40wvE)RPFbr}yS3@l71F?tPz=P^(?RdWf+}GpQ02-X!$Sbh#+dW;C0>@t(yMQ;YC*!7p2P|6F_`Br$~C05*;h^E!HoEW"
            "e11FC{#NUcxG>vMtOtTAFd7FR=~bar+;L7Kg~w%Al4>9oiA7YEEG3$$o0ob#S3NnhP-+Gp1}v+xRr#P^<(3}ew<^vhuB1aZlm(+G"
            "XOXP>gN5afXcDiPyh<BKncp~F&i~lNU&73g1&|6ipi8KU{})>gdwK`738?hqmY8c4w$ILEG~}<I+4|g5;z8A#qQ;SA;;__K3E*rg"
            "2Y5XkANO!X>_A)Z<#gXb@8NMK{<ez69eA)HN$q6}!=hzF7>{q*1wm<}zFDYLGmajv3gP6c{-zcaK<Am>p{}EPz~B~GH<%E-gS#ke"
            "A!ui?mwK7c`!q^WBG>i^PmhfN;Ii~+A4iaN{@)86vM1|YDky>~#ZfpEiq*>ohnP_!hahKphd~@zO#VS_aO2l#5<3pn-4@~Txsqtc"
            "yn98ijRPDB1|}5;cs|D!a}+z44@;i;MXt4!_PIV&lV+ogZJ>8#-0wK?@%I|ieO8XhCLaikzy_IxZD!~fc)E^!sky1$6y-v1m(({|"
            "f-P@Ooe07?CHhOH#&Sj=p6di~z9QJ^WN7LdL&UZbGhHT5#7%|-qky$8+JZ2(Vh8yb%e@`B$jF%Bvv=Wk&5F%DfnBR|IJf0g?$Rat"
            "=o=&VuGQo?rMtGr!H|Jy!9#2Vttb|<CvZ!L+AnfqvnNYdwNioB6NPYn631GWF(3J>U$lrIjDumiUw6j?3b{#dSWe~mulIqibry04"
            "`2c|te*=f7)2X!9v0~`ghbh`NYOM)bxdu7Cg7<+crR{r1!qRhv_S;i;U&01B0KBh3Wf0&4D*_TdK_Z|rr6JG43@!Ru1M-tuYtn0@"
            "|ELS8eH9OJV|y%;!|UF?gn+RGw%@fYl4n;&uIO;jdyY6sWpEwgsQs6q7_|Z^&4NZ}xFHxVxfZJRaK{ZVyxzrY3(WD4FrY{#nBYCe"
            "T0QURTLwvSXW|Cl@NPAOGK+tBjg8(e`LyCYj*7%Y6qWXsf@+{zv=Y+Kwu&t2`Tyq1e48N{zWRN;l(m3T|BNYiVA6|fdriE-4v|?P"
            "{Appfr+r_$ZebnK{ckz+WmPD45=SR?bn@_!X*UQ;O!{q$7S{TTTMc%1^}uHZh00ZCH(RZ16{$*|_u_ppM?aY9yYr<1!TSi7HJ`u|"
            "&822Yz)LIuTag|tC9F%~7J#M37rekRDy_Hx>EBK6wyqj2J}6*v3@E2)87c1NV!B4=Ks^Uz!pvDZ#*CWLyjasxTJ7ihJJn_Z&l_U!"
            "04;Bg)j5#R(yeWP92Ure3n18;2Nlues$t43FU!vE=HSF=%twf;sNfdwq)|4alu`3ryXyl-!8GedmY2adU7B-hFpWQWt-}A;=}xX)"
            "Xb^`%f~m-kYjv9SNuxHAg(MM7ED<>BpKzaO{_ktZ;_Apj@ThO_>Pdn!5i?l9=#N{UfvZ)4US&_8ImIzrgFe-CTk+8Jo}#g+c*NQ2"
            "3uH-2h8S9j5gaW!<R?RCj4%E_aB}Q-$Eu??D2Z4=4y|CnQajE%5OC(rMYvnwLH5j60X{d(4A3|RxXo)1|MsSX4&(hjOIS1221;E)"
            "nb(gf4mErZ;J?VGGcz`5QFp!o{-$Tq8{0!cWR0UeOnMD$s&{9z;Ck)vH_cox7)@1(?vLXN+JV1HV7fJ=AEcU~^Ba0ru@Cvr0=ZBm"
            "%bQGS=ej;30)^>|*f5s$S)&3YOdG{R<Zr|PITBM2o}hXT00Fok&_)0NeGNZ_vBYQl0ssI200dcD"
        )).decode('utf8')
        self.assertEqual(
            "console.log([1, 2, 'Fizz', 4, 'Buzz', 'Fizz', 7, 8, 'Fizz', 'Buzz', 11, 'Fizz', 13, 14,"
            " 'FizzBuzz', 16, 17, 'Fizz', 19, 'Buzz']);",
            self._deobfuscate(source),
        )

    def test_scope_aware_decoder_pairing(self):
        alpha1 = '0,Fz)`Q(lH=j5gK[i8~mJt_b&qr/fW^Y2]?#|@.!$cLZ9BN>A1o7ye+D%IM}O6;pV:P*E3CRnxXSh{wvaTUuk4G"s<d'
        alpha2 = alpha1[::-1]
        # Verify the test fixture is meaningful: cross-decode must NOT produce 'push'
        self.assertNotEqual(_decode_base91('fOg=r', alpha2), 'push')
        esc1 = alpha1.replace('"', '\\"')
        esc2 = alpha2.replace('"', '\\"')
        source = '\n'.join([
            # Shared string table: idx 10="push" (alpha1), idx 11="log" (alpha1)
            # idx 12="push" (alpha2), idx 13="log" (alpha2)
            'var table = ["aa","bb","cc","dd","ee","ff","gg","hh","ii","jj",'
            '"fOg=r","#ZlH",";^{aV","D>UT"];',
            # --- outer scope: decoder with alpha1, accessor pairing ---',
            'var cache1 = {};',
            *self._decode_js('dec', esc1),
            *self._access_js('acc', 'cache1', 'dec'),
            'var results = [];',
            'results[acc(10)]("hello");',
            'console[acc(11)](results);',
            # --- inner scope: same decoder+accessor names, alpha2 ---',
            'function inner() {',
            '    var cache2 = {};',
            *[F'    {line}' for line in self._decode_js('dec', esc2, indent=8)],
            *[F'    {line}' for line in self._access_js('acc', 'cache2', 'dec', indent=8)],
            '    var items = [];',
            '    items[acc(12)]("world");',
            '    console[acc(13)](items);',
            '}',
            'inner();',
        ])
        result = self._deobfuscate(source)
        self.assertEqual(
            inspect.cleandoc(
                """
                var results = [];
                results.push("hello");
                console.log(results);
                var items = [];
                items.push("world");
                console.log(items);
                """
            ),
            result,
        )

    def test_assignment_table_removed_even_if_not_var(self):
        source = '\n'.join([
            'var table;',
            'var cache = {};',
            'table = ["aa","bb","cc","dd","ee","ff","gg","hh","ii","jj",'
            '"fOg=r","lrCD^","#ZlH"];',
            *self._decode_js('decode', self._ESCAPED_ALPHABET),
            *self._access_js('accessor', 'cache', 'decode'),
            'var results = [];',
            'results[accessor(10)]("hello");',
            'console[accessor(12)](results);',
        ])
        self.assertEqual(
            inspect.cleandoc(
                """
                var results = [];
                results.push("hello");
                console.log(results);
                """
            ),
            self._deobfuscate(source),
        )

    def test_assignment_table_with_shadowing(self):
        source = '\n'.join([
            'var table;',
            'var cache = {};',
            'table = ["aa","bb","cc","dd","ee","ff","gg","hh","ii","jj",'
            '"fOg=r","#ZlH"];',
            *self._decode_js('decode', self._ESCAPED_ALPHABET),
            *self._access_js('accessor', 'cache', 'decode'),
            'console[accessor(11)](accessor(10));',
            'function inner() {',
            '    var table = [1, 2, 3];',
            '    return table;',
            '}',
            'console.log(inner());',
        ])
        self.assertEqual(
            inspect.cleandoc(
                """
                console.log('push');
                console.log([1, 2, 3]);
                """
            ),
            self._deobfuscate(source),
        )

    def test_an_accessor_declared_in_a_try_block_inside_a_loop_is_resolved(self):
        self.assertEqual(
            'console.log(\'log4\');',
            deobfuscate_source(AN_ACCESSOR_DECLARED_IN_A_TRY_BLOCK_INSIDE_A_LOOP, execution=ExecutionModel.module),
        )

    def test_a_function_holding_a_decoder_is_no_decoder_of_its_own(self):
        self.assertEqual(
            'console.log(\'xFizz\', \'push\');',
            deobfuscate_source(A_PROGRAM_FUNCTION_HOLDING_A_DECODER, execution=ExecutionModel.module),
        )

    def test_a_call_before_the_accessor_is_assigned_stays_a_call(self):
        result = deobfuscate_source(AN_ACCESSOR_CALLED_BEFORE_IT_IS_ASSIGNED, execution=ExecutionModel.module)
        self.assertIn('early = acc(10);', result)
        self.assertIn('console.log(early, \'Fizz\');', result)

    def test_an_accessor_called_in_a_with_body_keeps_its_machinery(self):
        result = deobfuscate_source(AN_ACCESSOR_CALLED_IN_A_WITH_BODY, execution=ExecutionModel.module)
        self.assertIn('console.log(\'push\');', result)
        self.assertIn('console.log(acc(11), k);', result)
        self.assertIn('function acc(index)', result)
        self.assertIn('function decode(str)', result)

    def test_a_script_storing_on_the_global_object_under_a_concealed_key_is_decoded(self):
        source = (
            HEAD
            + decoder('decode') + '\n'
            + accessor('acc', 'cache', 'decode') + '\n'
            + 'this[acc(11)] = 1;\n'
            + 'console.log(acc(10), Fizz);\n'
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                this.Fizz = 1;
                console.log('push', Fizz);
                """
            ),
            deobfuscate_source(source),
        )

    def test_an_accessor_in_a_block_is_decoded_inside_it_and_after_it(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                {
                  console.log('push');
                }
                console.log('Fizz');
                """
            ),
            deobfuscate_source(AN_ACCESSOR_IN_A_BLOCK_CALLED_INSIDE_IT_AND_AFTER_IT, execution=ExecutionModel.commonjs),
        )

    def test_an_accessor_in_a_block_called_only_after_it_is_decoded(self):
        self.assertEqual(
            'console.log(\'Fizz\');',
            deobfuscate_source(AN_ACCESSOR_IN_A_BLOCK_CALLED_ONLY_AFTER_IT, execution=ExecutionModel.commonjs),
        )

    def test_a_decoder_in_a_block_read_after_it_decodes(self):
        self.assertEqual(
            'console.log(\'push\', \'Fizz\');',
            deobfuscate_source(A_DECODER_IN_A_BLOCK_READ_AFTER_IT, execution=ExecutionModel.commonjs),
        )

    def test_an_accessor_in_a_block_of_a_function_is_decoded_after_it(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                {
                  console.log('push');
                }
                console.log('Fizz');
                """
            ),
            deobfuscate_source(AN_ACCESSOR_IN_A_BLOCK_OF_A_FUNCTION_CALLED_AFTER_IT, execution=ExecutionModel.commonjs),
        )

    def test_a_call_after_the_accessors_block_stays_where_the_file_may_be_an_es_module(self):
        result = deobfuscate_source(AN_ACCESSOR_IN_A_BLOCK_CALLED_ONLY_AFTER_IT, execution=ExecutionModel.module)
        self.assertIn('console.log(acc(11));', result)

    def test_a_call_before_the_block_declaring_the_accessor_stays_a_call(self):
        result = deobfuscate_source(AN_ACCESSOR_IN_A_BLOCK_CALLED_BEFORE_IT, execution=ExecutionModel.commonjs)
        self.assertIn('console.log(acc(11));', result)
        self.assertIn('console.log(\'push\');', result)
        self.assertIn('function acc(index)', result)

    def test_an_exported_cache_stays_declared(self):
        source = (
            F'export var cache = {{}};\nvar table = {TABLE};\n{BUFFER}\n'
            + decoder('decode') + '\n'
            + accessor('acc', 'cache', 'decode') + '\n'
            + 'console.log(acc(10));\n'
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                export var cache = {};
                console.log('push');
                """
            ),
            deobfuscate_source(source, execution=ExecutionModel.module),
        )


class TestStringsSlicedOutOfOneLongString(TestJsDeobfuscator):

    def test_every_call_slicing_an_encoded_string_is_decoded(self):
        self.assertEqual(
            'console.log(\'push\', \'Fizz\', \'log\', \'push\');',
            deobfuscate_source(A_PROGRAM_SLICING_EVERY_STRING, execution=ExecutionModel.module),
        )

    def test_a_long_string_the_accessor_spells_out_is_decoded(self):
        self.assertEqual(
            'console.log(\'push\', \'Fizz\', \'log\');',
            deobfuscate_source(A_LONG_STRING_THE_ACCESSOR_SPELLS_OUT, execution=ExecutionModel.module),
        )

    def test_a_call_whose_decoder_a_direct_eval_rebinds_stays_a_call(self):
        result = deobfuscate_source(A_DECODER_A_DIRECT_EVAL_REBINDS, execution=ExecutionModel.module)
        self.assertIn('console.log(S(2, 5));', result)

    def _pass_alone(self, source: str) -> str:
        """
        What the pass alone makes of *source*. The pipeline writes a short long string into the
        accessor reading it before the pass runs, so only the pass alone reads the name holding it.
        """
        options = DeobfuscationOptions(execution=ExecutionModel.module)
        return self._run_transformer(source, JsBase91StringDecoder, options)

    def test_a_slice_read_through_a_computed_key_is_decoded(self):
        self.assertIn(
            'console.log(\'push\', \'Fizz\', \'log\');',
            self._pass_alone(A_SLICE_READ_THROUGH_A_COMPUTED_KEY),
        )
        self.assertEqual(
            'console.log(\'push\', \'Fizz\', \'log\');',
            deobfuscate_source(A_SLICE_READ_THROUGH_A_COMPUTED_KEY, execution=ExecutionModel.module),
        )

    def test_a_renamed_slicing_accessor_is_decoded(self):
        self.assertIn(
            'console.log(\'push\', \'Fizz\', \'log\');',
            self._pass_alone(A_SLICING_ACCESSOR_RENAMED),
        )
        self.assertEqual(
            'console.log(\'push\', \'Fizz\', \'log\');',
            deobfuscate_source(A_SLICING_ACCESSOR_RENAMED, execution=ExecutionModel.module),
        )

    def test_a_caching_shape_over_the_long_string_leaves_the_slicing_accessor_decoded(self):
        for source in A_CACHING_SHAPE_OVER_THE_LONG_STRING:
            for reading, result in [
                ('pass alone', self._pass_alone(source)),
                ('pipeline', deobfuscate_source(source, execution=ExecutionModel.module)),
            ]:
                with self.subTest(source=source, reading=reading):
                    self.assertIn('console.log(typeof acc, \'push\', \'Fizz\', \'log\');', result)

    def test_a_slice_past_the_end_or_of_a_negative_number_stays_a_call(self):
        self.assertIn(
            'console.log(JSON.stringify([S(20, 9), S(9, -1), S(-6, 4), \'Fizz\']));',
            deobfuscate_source(A_SLICE_PAST_THE_END_OR_OF_A_NEGATIVE_NUMBER, execution=ExecutionModel.module),
        )

    def test_a_call_before_the_long_string_is_assigned_stays_a_call(self):
        result = deobfuscate_source(A_SLICE_BEFORE_THE_LONG_STRING_IS_ASSIGNED, execution=ExecutionModel.module)
        self.assertIn('r = S(2, 5);', result)
        self.assertIn('console.log(r, \'Fizz\');', result)

    def test_a_call_in_a_with_body_stays_a_call(self):
        result = deobfuscate_source(A_SLICE_IN_A_WITH_BODY, execution=ExecutionModel.module)
        self.assertIn('console.log(S(2, 5));', result)
        self.assertIn('console.log(\'Fizz\');', result)

    def test_an_accessor_held_by_a_parameter_stays_a_call(self):
        result = deobfuscate_source(A_SLICING_ACCESSOR_HELD_BY_A_PARAMETER, execution=ExecutionModel.module)
        self.assertIn('return a + T(2, 5);', result)
        self.assertIn('\'Fizz\');', result)

    def test_full_fizzbuzz_sample(self):
        """
        The whole program is recovered from the obfuscator's output for an eleven-line fizzbuzz with
        string concealing alone: its decoders stand at the top, in a function, in a loop and in `if`
        bodies, and the names of the properties the program reads are concealed as well.
        """
        source = lzma.decompress(base64.b85decode(
            '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;1s?GOI-jn9ZCPGVfzyXn;9}d7)}>6$vV{qUNBS9r5fag)srEN6PixxyXI;T{00IL20y?Ln_'
            'Rxpf7I?fmz$9^G{$%rQ0o;)F<|;#KAW%e@n$0B^Z`<YT<^n3frAnVqY3r>p$<c1UIgI5c;dzrgPeONir_9Ii)wREe{-HZ;Fe9K0T##'
            'u5V9#L7&ZarY&cfMuXx5qP&C}F08#!(`OIeX-Nhg`z*X-2_ux&tH8-{=yH|19AvZ+d>=$%wCJ>voZs3Jb_aDDpx&)1Jhv(x8oFxHzv'
            'y#evjb;Wh*O#Sl633wCajE9HKkBR*RGLBHnyU&ocVA_^SwjC>HC6b{c*xm-^+C@C9y0c(mwg~ze=+`_R3-4|qav=dTg%9bp`#Go{j9'
            '~w;jNsr+Tv5Kl^R=?GoqX6pmE<|lI!3%FJ)qh9rZ|_tnIELIPk)hSN{AwGNEsr7QqIfO|Do~p@W;Xd*?8x05iNc^*wcv*hYR^Vfa(n'
            'LpRYZlGH<xWMg%$q;88m<-T|%Qv-i#im9|Q1*lM=WSzJR5GNtbgP=N_7g|XZ8zH}GPk~;ShM{A&p)H?HGxR}Qex5U?$r~}v^2c=i_6'
            'wX)U}0A*x#hgTXSpP=WVAVfSj-n`?@n<!!&<}MjnQRJ5ut(_dMW8Abk)5Sq1?Bd+~Lp3{o#vxJBD`ID=#|s#07NgzL%tGu1?ILcjr0'
            '3;jPxfA=_)v%rk=dvx{J<VeUw9m^sPJl29L~EXkUpS&skPC3MP=y`lyD!oBjO2odMJrJ&g6PM^Q)j1v}7+_Ou8TY-MtF%j`GB_R+@+'
            'sXGLPsDmhKgxE}UGP@TGHO|KRnT3X{Uhw=hnq@@yd^DDgT$VcgoE77{}t9cHOn}!n}FmRaU&taeK)|Q_)wYczS39~l36CV;eeU^ELn'
            'A1iuC(oZCJUf8ANP<U50zDbxE*Ql_81wVx6vRvdFEx5zL(WuXwHx;=#dKiKfRXnCnls5dp6C*BuJndn05bgJ3H&e`oGoQokv+Myqhe'
            'rRHJN_?*`p;%q!TJBB#{T|NC??*nbzouK<@W2+hC?h+j#BkOC3P{n|2Z9^n(s06M%r@PA-BOG87IU7zocFFGKU~|||Ktm@Zh0>+D3e'
            '5QWebGRz-zJ9OoLVgGAD#mmEXcV@vTz;SzDQO&hB!As7lmUW7-+H32@&uA8A+OPvltg7hDiTm5JNe|`SoXlunL#sJ<Un9)|`C=$NXb'
            'KZvbO4B|z+H#Z20PTv@>iOMePzSZx;J{qwTCmw5Krk`f@GT8+{AV{SN*rKipZ4((@!?gJ%CDYYFkSWOxSXNIGhKq7~hIGlf%GUsyS%'
            'FuFZE1E2vP)Pm&mM%OUPS3J%r;kw+==a~ZUKbhEVSYS5#yXJLto-cK8(I@HPc1OQb=3||44TgHqrg#r?ob5Hv)UA-t<_=ohqNiQ+q;'
            '1j1#O)MbHLO1(4Q-w2E4`ij=3Ihg`&ED6A0D~gvFQ9OiT#&l=DAUs#fspBAtIyd<Dy$Qdk67i95>}!vggZw3eXIYLaD7lws&kSbdb)'
            '|LLy0NNj7HoSBmnE9y~qBx&2VLA2*&VE-;-*h^~zRm!L91lOIUCpDN7O7fioCV=5^@i+QfBlb04-x541rY4levD<_cdEBfMgv%Y=RB'
            '3~q@Rk&|{z>~MyJL{d?bZfaj?=SguoIWXPwUqoWguGJVisCUym4#g%p#Ij1KRMEeMF-eamG3k%lCx4boi%s251tg*P$tN9?yKyX1FE'
            '2ljO|#(}L)hKF1G&2VeYQoii5o3rz;ApE-nMI7@10sz@qFNL>yN8sLs!W}i-Ihf4;X9zgC2%!v}?vJ7_+a4ffHA={)nEGjdbuqinDa'
            '<BAgxrqC|^NG=f5Pz-9LL;eSXts>vgeSOG<fw1ZS~!?t$jcQRjlu9akuuho5w6te=2jmPl71fLm!<#N*Q8*AvNdek)!VMO0E5cQq&)'
            'm3Lryk-VHQPb%gBYXpJkY}0(I#KDIs6Xhqhr2b_TajIkxp>B&|n~jhd^mHkXq&5!Wk)7Bts2B;v@{!tC7=8p5wBV_hiD2OC<?B&JQ>'
            '_;vA!X3=QjgI8Y2Ut3Rj2T;%0N9e$e2UWILJ;DTC?yq+Flu534%U6rMGpkKv?Lrq!0yJe8O?!Ic;emz3U6;NLa^G0tPqdCd8lATV!@'
            '4uhz{!KQL~SeTLSm~0(BU#j*t4W^gD%s5i)kKuJTGoOlSJON3YXX(MH`27*M@=JxlKAJ1%aRTj&Z1?<+o%bo@sYrBi>sLHWhp#P(L9'
            '6N5*5VU#4&|&%Rjh^Ybe<+ryPFW(3346vYM?n+1s;X#w4r@IU`!SOXExv-pwG&4HK!$hxw3s?=yPjP-Y3_vrav$rvbd1_2&oEPgFZt'
            '|g4Y0r}&&Yelor6qjsLP+du-{@4HjnqaKaY$wHk00HL?zbOC!C1R-svBYQl0ssI200dcD'
        )).decode('utf8')
        self.assertEqual(
            'console.log(\'FizzBuzz: 1, 2, Fizz, 4, Buzz, Fizz, 7, 8, Fizz, Buzz, 11, Fizz, 13, 14,'
            ' FizzBuzz\');',
            self._deobfuscate(source),
        )


class TestAFunctionCallingNoDecoderIsNotComparedToTheAccessorTemplate(TestJsDeobfuscator):
    """
    A function of two parameters returning a call over a method call on an outer name has the parts
    of a slicing accessor, and only the decoder it would call tells it from one. Comparing a
    function to a template copies the whole function, so the pass looks the decoder up first.
    """

    def test_a_large_function_calling_no_decoder_costs_a_second_run_of_the_pass_no_copy(self):
        body = ' '.join(F'x{k} = {k};' for k in range(5000))
        source = (
            GLOBAL_BUFFER + '\n'
            + decoder('S_decode') + '\n'
            + 'function wrap(x) { return x; }\n'
            + 'var obj = { run: function (f) { return f; } };\n'
            + F'function big(a, b) {{ return wrap(obj.run(function () {{ var x; {body} }})); }}\n'
            + 'console.log(big(1, 2));\n'
        )
        tree = JsParser(source).parse()
        transformer = JsBase91StringDecoder()
        transformer.options = DeobfuscationOptions(execution=ExecutionModel.module)
        first = fastest_processor_time([functools.partial(transformer.visit, tree)])
        repeated = fastest_processor_time(functools.partial(transformer.visit, tree) for _ in range(3))
        # The first run builds the models the later runs reuse, which reads the whole program; a
        # copy of the large function costs about half as much as that first run.
        self.assertLess(processor_time_ratio(repeated, first), 1 / 5)


class TestTheDecoysOfADefaultedAccessor(TestJsDeobfuscator):

    def test_the_decoys_go_and_each_call_through_call_or_apply_is_decoded(self):
        source = next(iter(A_PROGRAM_HOLDING_A_DECOYED_ACCESSOR))
        self.assertEqual(
            "console.log('push', 'Fizz', 'log', 'push');",
            deobfuscate_source(source, execution=ExecutionModel.module),
        )

    def test_decoys_before_the_branch_that_decodes_go(self):
        source = (
            DEFAULTED_HEAD
            + defaulted('acc', 'dec', order='3405w12') + '\n'
            + 'console.log(acc(10), acc(11), acc.call(void 0, 12));\n'
            + decoder('dec') + '\n'
        )
        self.assertEqual(
            "console.log('push', 'Fizz', 'log');",
            deobfuscate_source(source, execution=ExecutionModel.module),
        )

    def test_an_accessor_whose_decoder_is_read_through_its_copy_keeps_its_decoys(self):
        source = (
            DEFAULTED_HEAD
            + 'function f() {\n'
            + '  {\n'
            + '    ' + defaulted('get', 'dec', order='w') + '\n'
            + '    console.log(get(11));\n'
            + '    ' + decoder('dec') + '\n'
            + '  }\n'
            + '  ' + defaulted('other', 'dec', order='w0') + '\n'
            + '  console.log(other(12));\n'
            + '}\n'
            + 'f();\n'
        )
        result = deobfuscate_source(source, execution=ExecutionModel.module)
        self.assertIn('return y[cache[z]] = other(x, y);', result)
        self.assertIn('console.log(other(12));', result)

    def test_a_call_through_an_optional_chain_stays(self):
        source = (
            DEFAULTED_HEAD
            + 'var r = acc?.call(undefined, 10);\n'
            + defaulted('acc', 'dec', order='3w1') + '\n'
            + 'console.log(r, acc(11));\n'
            + decoder('dec') + '\n'
        )
        self.assertIn('acc?.call(undefined, 10)', deobfuscate_source(source, execution=ExecutionModel.module))

    def test_a_call_through_call_stays_where_the_program_replaces_call(self):
        source = (
            DEFAULTED_HEAD
            + defaulted('acc', 'dec', order='w0') + '\n'
            + 'var original = Function.prototype.call;\n'
            + 'Function.prototype.call = function (receiver, index) { return "called" + index; };\n'
            + 'var r = acc.call(undefined, 10);\n'
            + 'Function.prototype.call = original;\n'
            + 'console.log(r, acc(11));\n'
            + decoder('dec') + '\n'
        )
        self.assertIn('acc.call(undefined, 10)', deobfuscate_source(source, execution=ExecutionModel.module))

    def test_full_fizzbuzz_sample(self):
        """
        The program is recovered from the obfuscator's output for an eleven-line fizzbuzz with
        string concealing alone, where the accessors default their decoders and caches, stand
        among decoys, and are called through `call` and `apply`; each decoder is declared at the end
        of the block whose strings it decodes, after the calls.
        """
        source = lzma.decompress(base64.b85decode(
            '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;4>)}SzQ1#9ZCPGVfzyXn;9}d7zoAjs^AQd`G2M&Xql@}Uz+v0Gc*<I-`?g6Pb^zB+*eI~'
            '_TXz#3WDhN_E@Y1tfNoVZ-@$H7;XxKsu)XtD9ZevwZ|7ePE(0krt-$^V0aRvNiN;^E45KnMap?9{=M{|GD;zg&RT$St{3JW906|~'
            'CsJJpQVCEdr1Dh(wcW*V4Di-`?zCVQwcdu*fICRPiCp6RdFpb{<h_Z^|4~IH^?$z*LIi+@6m`XFyYp{bs=Szrb)*KuWG$RVnF8^S'
            'RoAvBR;bCKrGNIW7uftdRy4`@7v0S%Wyu~Vr-dKaaBD-^<wxq@7hpw;|B!=iJ7P(~Mjiz5#$g?mhndhO+>*F)4NYln^L1>!i?9Hx'
            'e)6Y6X|CKC_6tU`WlYq)s&_V~He`ONyR<sPPTb6T?K6dQ3N{YkB^K3o3kKpv137s!o+8CJWo{kW;G)HN-#sw6v=N-dVClZ;+zM=4'
            'U5LN>DG~A^qSK+>4>M!F=o4No&Zt=)t44h`{tiXd-xc=z{KZJ<@{{JK!vCt%CQnz-;e8ZmyKQKmZBr>B(Oa6D{9rAq{=uY?4gg?N'
            'cGq8fxM=dI#+8ts6o;mYh9}f-E?q-;V+$VNTxl?>ng@<2v-}BljpyiBQ!N}vBV&$mTqa6Mxb3#-qdTAY%+-Rw@B3MIaAyBk=P`o5'
            'aIn-D%1G?)kC~=MShlO3eDzY`D5P-p*IGsY3)_L{EYR7l53zSCcd~CC!34sh7ba|OM;VQPu5;B*!-SQo|4Mpf9t@JW(>YnmwDwR)'
            'X?e-gPZ3+cb>(?eB(6@QPcFkSS|IM6Oa8%$hxZR<GMH6CMI8v{X6GMOvSP`|vXV=1zdiLv7M40%E;h%GJm+>2`q|YzrxocjRp&-|'
            'jGoi+X7Hszb>l&7bCZ*J3gWjQ{DMSPW0^{VGG`VWQDFe@T&QsjlnY07wzPfz#8We`lGi5Y%~NqjYMh8bNPxgjHfzX5lKN{&|Alzi'
            'ber)r*Ys*;fK9Zz=Uz&zA2K}2GtM1<u=MlSvs1mKlJSS5%x6TF+?htmFkfSV%($$Rc6maagZ7?&NdfP=y&?ij;N$Ib<~-!I44we}'
            'xqKhGkga3?;pwvNO{UU`f>F{*??hRO$KX}``NQh`9K2g%ffMe*b*PI(aUQnJHj%m@zD2hd6>0<T2$pn_k$7sf(~A~{O<y!X5go|k'
            'sv?rCyp2A<!B7dyAy)@W>BKmP>m2us8JVq{)-xOb-3YCdX-@_^kyScDv$zy$%HCy;-_^#WHQ1w^sx{#K^Ko4Gf?3u?2N(&<5--;v'
            'W%`6Z+3CrT;NSav8Y%q4m&D4x<<4i84~{0C)cx$|wy+O2-oRKn&z)B3i3?Ry36ky~LJ^ZV)f*}edE->V_uFTlVs43a!3mT&f+N_s'
            'bG^j|aDHcdd@;Q|A%r)9Z%hv6!D;eMhE;BK0O2V2wuMDxl&N!?f&gt<6>ZN+Lhv5Sl;vHCxDZ9x`<)33!u;>?Z7k}bBCXRcGD)0_'
            'xuQR)oVcIj)Ih2~_4kP&<em0xe)f0)j6(0K`r6=EaaRRiIz)Q5h&tb(%qeP=C-9%EYjw@R9F2TMPeA=W?NP|E^i2;i<CC!^|M?Ts'
            '0D{WLmvys-=IQL$>%Ia5BrT>hYTJ=QQpSPdHk29beFV}X+uZymb`R$(<(Ft;K+r2K091e3%$7A8>&RZC_bYSQ(tw0rFG72sZR&aq'
            'n#Kp^4}faa$vEwI^yR<>+!FMS5S1Va$L$p-VQ9BP1&gUnX_6P8gkWDHh^berRCq)3Rin7O@)p0lo^f+WPj;53_S<U~taTTe+E<0i'
            '({i1{<m!KdzX|ACWzds_NNk#tXOmpyyQ$RxuhBzFWs+}K?1;sRIP;9PR55W8{!%h8Dm$>A8*y`~GyBmBD8X<E4+1vEwIOo{|9m?k'
            'oWq{SpsF-L68;DdrL3xz27TYO%RBqS`tHS!>i-yV1IT7@NQT9k(K2(5)gC3?tgS~hZflKXx60u4$9tQgkrS&hT<NWcEHA*ULTW(`'
            'xO~?q+mb4CSpnHz*`y-qd}^O#ZWn3M_~2^kz-~$AAD{;q;5lstsI~S|9|1Bvo1ulW-Z2;H?}6VSkp*K6rtWb`McBX4(%|^+3a#Pp'
            'J>ykn>GC?h_4_4`f}-nMeL+ej=yY&Cb%V&D7@F%mzW1uS^R?j}Ce#y+s_rDX>Aq@k1RL0YXlm7JH2A~aqMNumYnp)>4widj`a$ds'
            'Y=Bu@6KjM$$EZLDafZZ(_(8(U?14{cdXSS=x$7L{9(0cf1tFX_@WstgKZ2!iy@oa5|FpPFhpXAgvCEz_9J&1grZlEHz|<qF!PX4x'
            '0$L<f8A_tcl)rWe|E-C;0lM1dOW~I|Y`67t#|cnIQh_m%@LVGV&J-iY<sY>%_^P<q3`NP``0i>HV{BogTvV_cF0os;C`7*48Bs{Q'
            '`(xS$wns3t_IQ|WSP+|340a1F6TAd^u#t)~w6IpGG33u%T)w$52AhDGc@_m)J@hZWt9Oh`cV&o(?Fz?#NZzZ&iU=#9;8FZePvWon'
            'N%lZeuWXx;fESwNhAZ!Q%X{v<;>dp3v6?DmZWbTphR}Ht(fZuv-i)Cuy$2L5<yl!==tXte2c>2u$U04$E4>`1aF2xs+Ks{?gQ1^J'
            ';w35|oJ7uK97sg0O%<OwvZZm}ylgu-R#Js@djFB9T92!oPA#But~vB84FC^6bXnD%!|PT9=iD#JS^TgmLF;^(Di@~;Wt+poq~LZK'
            '*b^olS)xgZZH(Kz)YaT4o8O4-b>H#;HC{p#w~NV)lx&17|LY_#AQ{yiTmOf-Q2uuqO?q~b8RURz-)f8(tztSojk0b-RS4DSs5Nt2'
            '?5;RNXH50wy4mqIorHBjME9B-0R5IQa`#hs;3TN6iKe_)JD4hFz<w&(448|+6MhhX#TKyge<m8RRHH5?gQ8x+94xB4{dASz5X4kE'
            '<QMS1o*k22k1XnOf&M1G-7VY>v|B$uZ~>jvJO9;mbRoz9agU8h*+QwQLQZ5XG=GoC<L!<%?~bMd(2OUMNZ>|+8o(;Sx5-w{N?5fj'
            'sRlUK!>j$Fm}Xx6v=Je=4bF((Pe2mgp<_nWe@HK2C5Y^#v;AFkK#jm(>AwU1Z_l;OM-rWWzsJsV&&n}k*2lJbJ*CD;|2R*9PrGV^'
            'K~!Y~n1GAvgY``j-;xLlgQ5hrzXht4s?(RLUeF+xy8#XXv7clp0Alr&9aekKhx$K^qHtx%VuU5#4=j#LE7lpRgxblGoW98a=<}%R'
            'B*Z@-J<dcMF}ms7&UXmVMs^6Mx!2gsx#Nc&^ZsyR*8p3-l?AzyHj4_GNtZf2J+f~IH4m@5-c?w-Tx3Ot>2};-cjQ9mXN0QKW<0?='
            ';U{u$$X9FoJ*B>o8aDtKgHZn*RkklFC@Kd?Q|4B_a*)ugBJrZ`t2(uZRxhg#NTkhn$4VumuUbOQl2}1U=ANxp-3IW+uyd!3`tAja'
            'Y%$hxeQV$)OYXJX59a^!DcO$azxXk$Yk#bK1k1rRgO-8c6_qT;L2r0*so<nbyc$P<el3SY(U91f0W*hs-lMfux5LY_t<n)jEcD8m'
            'C_Z)6CtYSGARX#^mVGrmp3f&09Pj{ngSNl1*4fTVzl&&P<30f+f-2d-pT1q-vhJZh>B*>otn;w=g+B8GcP4SQk<LKSe8aOQ{kgo%'
            'nlNfqZPKe7WKRMz83x^q2hC4>s)_yG4fHKH)kDmYsj=E<hZ*F1^XC&nO||`vZ1Zu{1r*9<e&z$38is-=5{}oNl*}v15uY1w|M~jb'
            '3XU+TV_=%3+Z?yDP6*<=X{ALF1d_7>8h<?L_t18sS=)X25R`p1O>q-^(M^m3b?>C^c-HnZku58{=EE2VRCg^vjcs**0WX0phH;Q8'
            'C=%1u6hgi&WuAFs4oZ|gR@W~9PM|EK5ZQC~{b*Q9WN+eYibeG;U32Ms4}3{)ipU^P<}t59bmGTw-787%d@&BNr%r;C6h#K5Vl1qq'
            'a;Or+38B)?_LpuG!z<_R0)2l3k$xX*5^Tj2-#6*URKeTT#Zk~*UWUZW)_0nzv~Q8@ypT$&`HkSS85jJ`79*v2WT`)E)+hw89o=P8'
            '0s^`HI(#NKy$K0^*QC~z)!a%*C9QU$kZ99%dNQmu_0x|k!EMw0d8|?sv7aaks&_5^-4!xhmircm@Ry|CkDHA?3DJDq#pffnZAU{}'
            '55%aFeKJ`S+R7b+E~A7g#%S?_ZZQe>jVnU&k`vpYh>@iKhuWooP;#=0>qe7|5vX1q+g)A2d+-Q@9Z&xN@y?tqgoB%$7jkF5PKR=}'
            'V>C=Er3b)g6i~xrBNm7#QMavAlc8B}RG*NqQI-!ykj(42O0ypq(2Au!sNUGiNvobINyqulyq#Ejo?uHcZU)IsZmVppOFQFLLwLxg'
            'ffF>O07FVo^W%&lmS&4y-jgA1flok+{av^m;ApGMd`J%8mE4`e_5&4tb?VlrCXSO*33;$}kYN`X1@6-(JNc`}E{WUySe9iVhiNMV'
            'I&bMbZHRVyKcZ+pN)u~P=bqr2pyIR8n?U3cRXV?1*ccEU!5s<J7l7b}ZWA^8+6ze<&HtXDKk)Y^9wq<J0@N0^lStRuH_Vul1>j5A'
            'dZVjNPCx<2h2(1XP^AQX27qho4HSCcLTq4(ey)2hQ@Tr2GI$c={@Dg;kIN4Hucym-W*Wf95dvv=(mj&E;Fw#F((d2g0q+9Va?c7n'
            'Lv@cCjE2#)etvLzP;Ra5;=;(l`efP`NP`m+E%`wXKUI-fkJ(pLH7XoP0tPNE8jZpmlNC4*gjG?MOlb}6988BJK(78osI_aw(MfCy'
            'e%+&LiK9lP;kUsdNV(+)%gdma1pXbk$<o@cUU$$r%h^iqmDHK!cNLaZT__KN>zP-}0rqsG(hxjFjRGHEuc|wK&SB4eu3PkJ0kDZC'
            '${%OogV)Le!=*t-6o#`rz)2s{&BkX(Yb-cOs$dBY+p)4w$$=vRi8SmM_($?;Hn$8Es?Pg0;`xb~+%r&GdN{|{{2Kg2hL6JrTt5w<'
            '(19_3k23jjl4|^#xHG7qQy(N0^3zohd>xQpC0SpTulM|Yxb$G)Zx*b6z5Qn7WzVfg?&pE;9E_$(CyNi2&Juad>hsM3jeD%`mvJm_'
            'c2$j7h$x;D#Pu*-hI{vsi_^SGTI@%RIR*U)mg^;W<8=UtRCABlVQZ`%X|Au14k1FM=)-Tu8$ve92E(qCpcw3^yiEgja6{+cG&|1}'
            'J-}=j$^eiunKBu?X#e)P$Tus_mgUu<TST<bl|WJKIj-4AZ)Iq6>aW^=TXgv<eTBe9V64hJzQ+vSnx6WA)f{YTf^wFA3x>X)akk#K'
            'K=27Y$F(`FGhSe#nx?fT+x#RJ6RnZOw<-h{wK#RC2+p~y8eSdx=C>`liMcGVkOs`@Co4Jcj)6ZZ2tGyYAk9R0Ls5>-(D7K24}!z|'
            'Jt~%r6hEgMne!iz-?S~nyiBv5)dX55yqy#0+&8{UoHIkUP()t}4E!pE#l7If*#%{j&~My5aKwd3$=B9Ehvb@X(%Vl}+J^3B?_a*2'
            'GAGVc&NAlgC*G1U-`)E2ez4lj#Rq972n;KjPHPQciIi`Mw@xTrR@)6F7t04H4Rli~!)cIKBE?Bo*r4XQv{G-qu0mlLEk)8~#AB!^'
            'Cm59}am(2oieq^rV$HPRBE@AnN>0|J2%*e1`+jkKNLe!%@JPs59Tg8oTagMcq5#>&)9_GIjZfVF7O>-ekOdS*AAl#!G7Tf>mq8o4'
            'x}gTy!^sPEp}*IWL_R}L&CT0NR;H-w(T8@RMG(>2Mw_Pat*s~K_lA2sF+H9wvB@hgFPYsEYZ=LqS>R!YSUk=&jn8%FUTa~PMWC+d'
            'GntgF$^$)w=+1YKH4pm<rY4Dwp=E|5B-XiO=VjWY&NxdC!Z>;sd+x9j+;_+!cgBB@XndAfgwKk;Jc3iS5@`g-?Q&X1XWZ5TLiq6z'
            '#v-<^u;jPhtm^Trw*wxE^bwA=u+f6-b>Sxz`^f&~H9`?#;o?t&8=&))>YEB<WYmIv0{@#}J2!s=f!3Fgk%F0QcDzulwU&Awhs6x?'
            '`LJaE<`PW~Kj1sp`tN|ybmuo7&Kx5rdt$v#7B!P%+M7bq?=n3O&65zpAYu8YOMKF{nF8@+zq2JssfFI(lo5B%86~8K)Q$$Fv0*I}'
            '#}{kO;uXAwNV-cOa7-5xa+xCc!(%aBTJ?8Im^BPgRTBZ4ypG=Cfg;RZCk>JY9oW+hG=py~C>Au82iucbu83h5GEjoJgaW$8z%J_('
            'XozF?Jz3r?M3eSoLxkxn$M||ZCG;;yD?QU>1`YnmvFGNxsW7Ahc+-7zWfyDWL6}`e4rZR1Fz^8`7x3hcQQ`Tm=_y;a?sYZszpXQo'
            'C}PSpl-_(xzJD?&#R8tfzXkYoGys7wFg%-m`bFarRa9a4bKafNX@g9<r3Y;Z4iMyN{YUZk*xrAmxh@iUc$wu!Y6GsFuQjkEZHk)K'
            '&M3tp`J#SX)j4mvhRxL#@=-A+Zeg%m;pn6-`mD|U?hj(pTyMWIED(%VW}b{#1_Ld44K$MOeOvXi-lncP3PvkGk}!|2h7fiROsy4-'
            'o@&R>@{)`d4O9Yu)B_+T6HY38ouWhs17pA2)j}V@V>-s39gM9R{br(8)P8RpYJA>8`b=Pe`@qT?-vj=_XxtH#58mbq$t$Qma9Yb4'
            'kE%G(vO86L2<l8OprjHPX!(+=f5SAIolrH`ko)X5W_Ng`4Ji+~0zAb%_ErAg1smdrfG#ok`A7n8b5-lJ^9Mu8Qi^RwosxZ|NappX'
            '+SX3dwsCxZ&#K7AKv@5l7aG*Zd(J5zUyDv%XYPCWegpky{z2%po-c-ws3_x#e|DQca?tt7gjEogFGS16E4m_k`H-R0X@gODC*pP}'
            'Ma-%#PU4K<Ui%_W>6?`*uNX&OmF1m$=hj7}l+F$XonG@Z2ndjtI1vjc81$nXgj-`&f5=-9@S)u5LT=QUH>Zdkwc<^xS-P)<_>uj5'
            'fRbL@pQ$$#{#iP&{R@0!-ijncKM3)Ed_I5`5WEc~mrg?c89O6TUu)LcOi2w=$l|VUitYL888g__f}UaP-?x78;u_Gntrf|phm<r9'
            'kWFF6zWMu{WIiaxYMXyjN&^P(bsqA-w-dkYnfoi~ZzPk2o;OaK!J^hJKWS2unmIzy(G_HJ${!h^dbN;^nj;0$n@Y>-8BnLuL-<!+'
            'TU8wfFW=GYI)+wB?B<;xXjzg*3s)*U{g4rg&D<eJ70#bGZ^S4?b2$U*XriLmllPFEnugsZ#i)(MWBK*WKjOQ0N?Htvvq4Z!%X+@W'
            '8QLg))~RkXj_&vknB)^a!mz(4hYRQTIZsmNEGQMhldItZg4`#u$sz;W>&5dvS}3E%mR}ER9pbXA|2@GY#W}RNoB$<+00000hc^lY'
            'c6D?T00H$Zs%8KHfzY??vBYQl0ssI200dcD'
        )).decode('utf8')
        result = self._deobfuscate(source)
        self.assertTrue(result.endswith(inspect.cleandoc(
            """
            function fizzbuzz(limit) {
              var lines = [];
              for (var i = 1; i <= limit; i++) {
                var line = '';
                if (i % 3 === 0) {
                  line += 'Fizz';
                }
                if (i % 5 === 0) {
                  line += 'Buzz';
                }
                lines.push(line || String(i));
              }
              return lines.join(', ');
            }
            console.log('FizzBuzz: ' + fizzbuzz(15));
            """
        )))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameAboutConcealedStrings(TestJsDeobfuscator):

    def test_each_program_holding_a_decoyed_accessor_prints_what_it_printed(self):
        rows = A_PROGRAM_HOLDING_A_DECOYED_ACCESSOR
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_script_calling_its_decoyed_accessor_through_the_global_object_prints_the_same(self):
        rows = A_SCRIPT_CALLING_A_DECOYED_ACCESSOR_THROUGH_THE_GLOBAL_OBJECT
        self.assertEqual(
            {source: before_and_after_in_a_host(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_each_program_prints_what_it_printed(self):
        rows = A_PROGRAM_HOLDING_CONCEALED_STRINGS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_each_program_slicing_its_strings_prints_what_it_printed(self):
        rows = A_PROGRAM_SLICING_CONCEALED_STRINGS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_script_kept_for_its_value_keeps_the_accessor_it_assigns_last(self):
        source = (
            F'var cache = {{}};\nvar table = {TABLE};\n{CHAR_CODES}\n'
            + decoder('decode') + '\n'
            + 'var acc;\n'
            + 'acc = function (index) { ' + accessor_body('cache', 'decode') + ' };\n'
            + 'var x = acc(10);\n'
        )
        decoded = self._run_transformer(
            source,
            JsBase91StringDecoder,
            DeobfuscationOptions(preserve_script_return=True),
        )
        self.assertEqual(completion_values([source]), completion_values([decoded]))

    def test_an_importer_calls_an_exported_accessor_as_it_did(self):
        source = (
            HEAD
            + decoder('decode') + '\n'
            + 'export ' + accessor('acc', 'cache', 'decode') + '\n'
            + 'console.log(acc(10));\n'
        )
        importer = 'import { acc } from "./m.mjs";\nconsole.log(acc(11));\n'
        rewritten = deobfuscate_source(source, execution=ExecutionModel.module)
        self.assertEqual(
            module_graph_behavior({'m.mjs': source, 'main.mjs': importer}, 'main.mjs'),
            module_graph_behavior({'m.mjs': rewritten, 'main.mjs': importer}, 'main.mjs'),
        )
