from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import code_units, node_executable

from refinery.units.scripting.djs import djs


_ASTRAL = chr(0x1F600)

_LITERAL = "'a" + _ASTRAL + "b'"

_ESCAPED_PAIR = chr(92) + 'uD83D' + chr(92) + 'uDE00'

#: Expressions that each build at runtime the string `_LITERAL` spells; F0 9F 98 80 is the UTF-8
#: encoding of U+1F600.
_PRODUCERS: dict[str, str] = {
    'decode_uri_component' : "decodeURIComponent('a%F0%9F%98%80b')",
    'buffer_from_utf8'     : "Buffer.from([0x61,0xf0,0x9f,0x98,0x80,0x62]).toString('utf8')",
    'json_parse_value'     : "JSON.parse('\"a" + _ASTRAL + "b\"')",
    'json_parse_escape'    : "JSON.parse('\"a" + _ESCAPED_PAIR + "b\"')",
    'json_parse_key'       : "Object.keys(JSON.parse('{\"a" + _ASTRAL + "b\":1}'))[0]",
}

_PROBES: dict[str, str] = {
    'length'        : '({S}).length',
    'index'         : '({S})[2]',
    'charcode_high' : '({S}).charCodeAt(1)',
    'charcode_low'  : '({S}).charCodeAt(2)',
    'slice'         : '({S}).slice(1, 3)',
    'split'         : "({S}).split('')",
    'split_length'  : "({S}).split('').length",
}

_NODE_UNITS: dict[str, str] = {
    'length'        : '4',
    'index'         : 'S[56832]',
    'charcode_high' : '55357',
    'charcode_low'  : '56832',
    'slice'         : 'S[55357,56832]',
    'split'         : 'A[S[97],S[55357],S[56832],S[98]]',
    'split_length'  : '4',
}


_NODE_PRODUCERS = frozenset({'buffer_from_utf8'})


def _fold(expression: str, environment: str = 'universal') -> str:
    source = F'console.log({expression});'.encode('utf8')
    printed = source | djs(strict=True, environment=environment) | str
    return printed.removeprefix('console.log(').removesuffix(');')


def _node_units(expression: str) -> str:
    return code_units([expression])[0]


class TestAstralStringProducers(TestBase):

    def test_produced_astral_string_folds_like_the_literal(self):
        for probe_name, probe in _PROBES.items():
            expected = _fold(probe.format(S=_LITERAL))
            for producer_name, producer in _PRODUCERS.items():
                environment = 'node' if producer_name in _NODE_PRODUCERS else 'universal'
                with self.subTest(probe=probe_name, producer=producer_name):
                    self.assertEqual(_fold(probe.format(S=producer), environment), expected)

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_folded_constants_match_node_code_units(self):
        for probe_name, node_units in _NODE_UNITS.items():
            probe = _PROBES[probe_name]
            with self.subTest(probe=probe_name):
                self.assertEqual(_node_units(probe.format(S=_LITERAL)), node_units)
                self.assertEqual(_node_units(_fold(probe.format(S=_LITERAL))), node_units)
