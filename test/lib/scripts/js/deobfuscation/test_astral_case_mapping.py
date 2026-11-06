"""
Case mapping works on code points, so a character outside the Basic Multilingual Plane, held as two
UTF-16 code units, maps as a whole: the Deseret capital U+10400 lowercases to U+10428, and U+10428
uppercases back to U+10400.
"""
from __future__ import annotations

import inspect
import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import behavior, node_executable

from refinery.units.scripting.djs import djs


_CAP = chr(0x10400)

_LOW = chr(0x10428)

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

_PROBES: dict[str, str] = {
    'mapped_string' : '{S}',
    'charcode_high' : '({S}).charCodeAt(0)',
    'charcode_low'  : '({S}).charCodeAt(1)',
}

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
    return F'({source}).{method}()'


_NODE_INPUTS = frozenset({'buffer_from_utf8'})


def _fold(expression: str, environment: str = 'universal') -> str:
    source = F'console.log({expression});'.encode('utf8')
    printed = source | djs(strict=True, environment=environment) | str
    return printed.removeprefix('console.log(').removesuffix(');')


def _host_of(input_name: str) -> str:
    return 'node' if input_name in _NODE_INPUTS else 'universal'


def _node_units(expression: str) -> str:
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
                    host = _host_of(input_name)
                    with self.subTest(mapping=mapping, probe=probe_name, input=input_name):
                        self.assertEqual(_fold(probe.format(S=subject), host), expected)

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_folded_case_mapping_matches_node_code_units(self):
        for mapping, (method, inputs) in _MAPPINGS.items():
            for probe_name, node_units in _NODE_UNITS[mapping].items():
                probe = _PROBES[probe_name]
                for input_name, source in inputs.items():
                    expression = probe.format(S=_case_mapped(source, method))
                    host = _host_of(input_name)
                    with self.subTest(mapping=mapping, probe=probe_name, input=input_name):
                        self.assertEqual(_node_units(expression), node_units)
                        self.assertEqual(_node_units(_fold(expression, host)), node_units)
        for expression, node_units in _ASCII_CONTROL.items():
            with self.subTest(control=expression):
                self.assertEqual(_node_units(expression), node_units)
                self.assertEqual(_node_units(_fold(expression)), node_units)
