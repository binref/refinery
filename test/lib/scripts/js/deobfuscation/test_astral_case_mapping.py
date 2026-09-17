"""
A JavaScript string is a sequence of UTF-16 code units, and case mapping is defined on code points,
so a character *outside* the Basic Multilingual Plane can be case-mapped even though it occupies two
code units. The Deseret block is such a pair: U+10400 (capital) lowercases to U+10428, and U+10428
uppercases back to U+10400. Each of these characters is a single high/low surrogate pair, so the
mapped result is again two code units.

The law formalized here is that folding a case-mapping call yields the correctly mapped character,
held as its UTF-16 code units and agreeing with Node.js — and that this is true whether the input
character is written as a literal or *produced* at runtime from its UTF-8 bytes (percent-decoded with
`decodeURIComponent`, or decoded with `Buffer.from(...).toString('utf8')`). Node.js is the authority
for the absolute answers, established below by running each snippet in a real engine.

For the two Deseret characters Node reports:

  String.fromCodePoint(0x10400).toLowerCase()   is U+10428, code units 55297, 56360
  String.fromCodePoint(0x10428).toUpperCase()   is U+10400, code units 55297, 56320

The tool reduces the whole mapped string, and the character-code at each of its two halves, to a
constant; which operations fold was discovered by measuring, not decided here. As a control, ordinary
Basic-Multilingual-Plane case mapping is unchanged: `'ABC'.toLowerCase()` is `'abc'` (97, 98, 99) and
`'abc'.toUpperCase()` is `'ABC'` (65, 66, 67).
"""
from __future__ import annotations

import inspect
import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import behavior, node_executable

from refinery.units.scripting.js import js


_CAP = chr(0x10400)

_LOW = chr(0x10428)

#: Each case mapping to formalize: the method applied, and JavaScript expressions that each evaluate,
#: in Node, to the same input astral character — once written as a literal, and twice produced at
#: runtime from its UTF-8 bytes (F0 90 90 80 for the capital, F0 90 90 A8 for the small letter).
_MAPPINGS: dict[str, tuple[str, dict[str, str]]] = {
    'lowercase': (
        'toLowerCase',
        {
            'literal'              : "'" + _CAP + "'",
            'decode_uri_component' : "decodeURIComponent('%F0%90%90%80')",
            'buffer_from_utf8'     : "Buffer.from([0xf0,0x90,0x90,0x80]).toString('utf8')",
        },
    ),
    'uppercase': (
        'toUpperCase',
        {
            'literal'              : "'" + _LOW + "'",
            'decode_uri_component' : "decodeURIComponent('%F0%90%90%A8')",
            'buffer_from_utf8'     : "Buffer.from([0xf0,0x90,0x90,0xa8]).toString('utf8')",
        },
    ),
}

#: Operations that reveal the code-unit structure of the case-mapped string substituted for `{S}`.
_PROBES: dict[str, str] = {
    'mapped_string' : '{S}',
    'charcode_high' : '({S}).charCodeAt(0)',
    'charcode_low'  : '({S}).charCodeAt(1)',
}

#: Node's answer for each probe, rendered as its code-unit structure: a number verbatim, a string as
#: `S[...codes...]`. The rendering is spelling-independent, so it pins the value and not the escapes.
_NODE_UNITS: dict[str, dict[str, str]] = {
    'lowercase': {
        'mapped_string' : 'S[55297,56360]',
        'charcode_high' : '55297',
        'charcode_low'  : '56360',
    },
    'uppercase': {
        'mapped_string' : 'S[55297,56320]',
        'charcode_high' : '55297',
        'charcode_low'  : '56320',
    },
}

#: Basic-Multilingual-Plane case mapping, which must be untouched, mapped to Node's code units.
_ASCII_CONTROL: dict[str, str] = {
    "'ABC'.toLowerCase()" : 'S[97,98,99]',
    "'abc'.toUpperCase()" : 'S[65,66,67]',
}

_ENCODER = inspect.cleandoc(
    """
    function enc(x) {
      if (typeof x === 'number' || typeof x === 'boolean') return JSON.stringify(x);
      if (typeof x === 'string')
        return 'S[' + Array.from({length: x.length}, (_, i) => x.charCodeAt(i)).join(',') + ']';
      if (Array.isArray(x)) return 'A[' + x.map(enc).join(',') + ']';
      return JSON.stringify(x);
    }
    """
)


def _case_mapped(source: str, method: str) -> str:
    """
    The JavaScript expression that case-maps *source* with *method*.
    """
    return F'({source}).{method}()'


def _fold(expression: str) -> str:
    """
    The expression `refinery.js` folds *expression* to. It is placed in a `console.log` argument,
    which survives as a side effect, so nothing but the fold decides what comes back.
    """
    printed = F'console.log({expression});'.encode('utf8') | js(strict=True) | str
    return printed.removeprefix('console.log(').removesuffix(');')


def _node_units(expression: str) -> str:
    """
    Node's evaluation of *expression*, rendered as the code-unit structure produced by `_ENCODER`.
    """
    stdout, error = behavior(F'{_ENCODER}\nconsole.log(enc({expression}));\n')
    if error is not None:
        raise AssertionError(F'node rejected {expression!r}: {error}')
    return stdout.strip()


class TestAstralCaseMapping(TestBase):

    def test_produced_input_case_maps_like_the_literal(self):
        for mapping, (method, inputs) in _MAPPINGS.items():
            literal_subject = _case_mapped(inputs['literal'], method)
            for probe_name, probe in _PROBES.items():
                expected = _fold(probe.format(S=literal_subject))
                for input_name, source in inputs.items():
                    if input_name == 'literal':
                        continue
                    subject = _case_mapped(source, method)
                    with self.subTest(mapping=mapping, probe=probe_name, input=input_name):
                        self.assertEqual(_fold(probe.format(S=subject)), expected)

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_folded_case_mapping_matches_node_code_units(self):
        for mapping, (method, inputs) in _MAPPINGS.items():
            for probe_name, node_units in _NODE_UNITS[mapping].items():
                probe = _PROBES[probe_name]
                for input_name, source in inputs.items():
                    expression = probe.format(S=_case_mapped(source, method))
                    with self.subTest(mapping=mapping, probe=probe_name, input=input_name):
                        self.assertEqual(_node_units(expression), node_units)
                        self.assertEqual(_node_units(_fold(expression)), node_units)
        for expression, node_units in _ASCII_CONTROL.items():
            with self.subTest(control=expression):
                self.assertEqual(_node_units(expression), node_units)
                self.assertEqual(_node_units(_fold(expression)), node_units)
