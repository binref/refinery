"""
A string is a sequence of UTF-16 code units, so an astral character such as U+1F600 occupies two
of them: a high surrogate and a low surrogate. Such a string can be written as a literal, but it
can also be *produced* at runtime by a built-in operation — percent-decoding with
`decodeURIComponent`, decoding UTF-8 bytes with `Buffer.from(...).toString('utf8')`, or parsing
JSON with `JSON.parse`, from a text holding the character itself, from one spelling it as the
escaped surrogate pair D83D DE00, and from an object key reached through `Object.keys`.

The law formalized here is that a produced astral string is indistinguishable from the same string
written as a literal: for every operation that reveals a string's code-unit structure, folding the
produced form yields exactly what folding the literal yields. Node.js is the authority for the
absolute answers, established below by running each snippet in a real engine.

For the astral string `'a' + U+1F600 + 'b'` Node reports the code units 97, 55357, 56832, 98 and:

  ('a' + U+1F600 + 'b').length          === 4
  ('a' + U+1F600 + 'b')[2]              is the lone low surrogate, char code 56832
  ('a' + U+1F600 + 'b').charCodeAt(1)   === 55357
  ('a' + U+1F600 + 'b').charCodeAt(2)   === 56832
  ('a' + U+1F600 + 'b').slice(1, 3)     is the two surrogates, char codes 55357, 56832
  ('a' + U+1F600 + 'b').split('')       is ['a', high, low, 'b'], char codes 97, 55357, 56832, 98
  ('a' + U+1F600 + 'b').split('').length === 4

The tool reduces every one of these to a constant: `.length` and the index read because both are own
data properties of the string that no prototype can shadow, and the length of the split because the
array it hands back is counted by the commas it comes back written with, which
`test.lib.scripts.js.deobfuscation.test_array_length_reads` states for an array literal of any
provenance. Which of them happens was discovered by measuring, not decided here. The invariance that
a produced string reads like the literal carries every probe, and the Node-anchored code-unit value
carries each folded constant.
"""
from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import code_units, node_executable

from refinery.units.scripting.js import js


_ASTRAL = chr(0x1F600)

_LITERAL = "'a" + _ASTRAL + "b'"

_ESCAPED_PAIR = chr(92) + 'uD83D' + chr(92) + 'uDE00'

#: Expressions that each evaluate, in Node, to the same string as `_LITERAL`, but build it at
#: runtime rather than spelling it. `decodeURIComponent` percent-decodes the UTF-8 of the astral
#: character (F0 9F 98 80), `Buffer.from` decodes the same bytes, and `JSON.parse` reaches the
#: character through a string value that holds it, through a string value that spells it as an
#: escaped surrogate pair, and through an object key.
_PRODUCERS: dict[str, str] = {
    'decode_uri_component' : "decodeURIComponent('a%F0%9F%98%80b')",
    'buffer_from_utf8'     : "Buffer.from([0x61,0xf0,0x9f,0x98,0x80,0x62]).toString('utf8')",
    'json_parse_value'     : "JSON.parse('\"a" + _ASTRAL + "b\"')",
    'json_parse_escape'    : "JSON.parse('\"a" + _ESCAPED_PAIR + "b\"')",
    'json_parse_key'       : "Object.keys(JSON.parse('{\"a" + _ASTRAL + "b\":1}'))[0]",
}

#: Operations that reveal the code-unit structure of the string substituted for `{S}`.
_PROBES: dict[str, str] = {
    'length'        : '({S}).length',
    'index'         : '({S})[2]',
    'charcode_high' : '({S}).charCodeAt(1)',
    'charcode_low'  : '({S}).charCodeAt(2)',
    'slice'         : '({S}).slice(1, 3)',
    'split'         : "({S}).split('')",
    'split_length'  : "({S}).split('').length",
}

#: The probes the tool folds to a constant, each mapped to Node's answer rendered as its code-unit
#: structure: a number verbatim, a string as `S[...codes...]`, an array as `A[...elements...]`. The
#: rendering is spelling-independent, so it pins the value and not the tool's choice of escapes.
_NODE_UNITS: dict[str, str] = {
    'length'        : '4',
    'index'         : 'S[56832]',
    'charcode_high' : '55357',
    'charcode_low'  : '56832',
    'slice'         : 'S[55357,56832]',
    'split'         : 'A[S[97],S[55357],S[56832],S[98]]',
    'split_length'  : '4',
}


def _fold(expression: str) -> str:
    """
    The expression `refinery.js` folds *expression* to. It is placed in a `console.log` argument,
    which survives as a side effect, so nothing but the fold decides what comes back.
    """
    printed = F'console.log({expression});'.encode('utf8') | js(strict=True) | str
    return printed.removeprefix('console.log(').removesuffix(');')


def _node_units(expression: str) -> str:
    """
    Node's evaluation of *expression*, rendered as its UTF-16 code-unit structure.
    """
    return code_units([expression])[0]


class TestAstralStringProducers(TestBase):

    def test_produced_astral_string_folds_like_the_literal(self):
        for probe_name, probe in _PROBES.items():
            expected = _fold(probe.format(S=_LITERAL))
            for producer_name, producer in _PRODUCERS.items():
                with self.subTest(probe=probe_name, producer=producer_name):
                    self.assertEqual(_fold(probe.format(S=producer)), expected)

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_folded_constants_match_node_code_units(self):
        for probe_name, node_units in _NODE_UNITS.items():
            probe = _PROBES[probe_name]
            with self.subTest(probe=probe_name):
                self.assertEqual(_node_units(probe.format(S=_LITERAL)), node_units)
                self.assertEqual(_node_units(_fold(probe.format(S=_LITERAL))), node_units)
