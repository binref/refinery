from __future__ import annotations

import base64
import inspect
import lzma
import unittest

from test.lib.scripts.js.analysis.differential import (
    completion_values,
    deobfuscate_source,
    module_graph_behavior,
    node_executable,
)
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator
from test.lib.scripts.js.ledger import before_and_after, each_program_still_prints

from refinery.lib.scripts.js.deobfuscation.b91strings import JsBase91StringDecoder, _decode_base91
from refinery.lib.scripts.js.options import DeobfuscationOptions

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


def decoder_body() -> str:
    """
    The body of a decoder over `ALPHABET`, as the obfuscator writes it.
    """
    alphabet = ALPHABET.replace('"', '\\"')
    return (
        F'var alpha = "{alphabet}"; var raw = "" + (str || ""); var len = raw.length; var ret = []; '
        'var b = 0, n = 0, v = -1; for (var i = 0; i < len; i++) { var p = alpha.indexOf(raw[i]); '
        'if (p === -1) continue; if (v < 0) { v = p; } else { v += p * 91; b |= v << n; '
        'n += (v & 8191) > 88 ? 13 : 14; do { ret.push(b & 0xff); b >>= 8; n -= 8; } while (n > 7); '
        'v = -1; } } if (v > -1) { ret.push((b | v << n) & 0xff); } return bufferToString(ret);'
    )


def decoder(name: str) -> str:
    """
    A decoder over `ALPHABET` declared as *name*.
    """
    return F'function {name}(str) {{ {decoder_body()} }}'


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

#: Programs holding the machinery of concealed strings in a shape that decides what a call of an
#: accessor returns or whether the machinery is still named, mapped to what Node prints for each.
A_PROGRAM_HOLDING_CONCEALED_STRINGS = {
    AN_ACCESSOR_DECLARED_IN_A_TRY_BLOCK_INSIDE_A_LOOP: 'log4\n',
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
            deobfuscate_source(AN_ACCESSOR_DECLARED_IN_A_TRY_BLOCK_INSIDE_A_LOOP, module=True),
        )

    def test_a_function_holding_a_decoder_is_no_decoder_of_its_own(self):
        self.assertEqual(
            'console.log(\'xFizz\', \'push\');',
            deobfuscate_source(A_PROGRAM_FUNCTION_HOLDING_A_DECODER, module=True),
        )

    def test_a_call_before_the_accessor_is_assigned_stays_a_call(self):
        result = deobfuscate_source(AN_ACCESSOR_CALLED_BEFORE_IT_IS_ASSIGNED, module=True)
        self.assertIn('early = acc(10);', result)
        self.assertIn('console.log(early, \'Fizz\');', result)

    def test_an_accessor_called_in_a_with_body_keeps_its_machinery(self):
        result = deobfuscate_source(AN_ACCESSOR_CALLED_IN_A_WITH_BODY, module=True)
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
            deobfuscate_source(source, module=True),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameAboutConcealedStrings(TestJsDeobfuscator):

    def test_each_program_prints_what_it_printed(self):
        rows = A_PROGRAM_HOLDING_CONCEALED_STRINGS
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
        self.assertEqual(
            module_graph_behavior({'m.mjs': source, 'main.mjs': importer}, 'main.mjs'),
            module_graph_behavior({'m.mjs': deobfuscate_source(source, module=True), 'main.mjs': importer}, 'main.mjs'),
        )
