from __future__ import annotations

import inspect
import unittest

from test import TestBase, opportunity
from test.lib.scripts.js.analysis.differential import behavior, node_executable
from test.lib.scripts.js.analysis.write_positions import WRITE_POSITIONS

from refinery.units.scripting.djs import djs

_ARRAY_INDEX = ('[1, 2, 3][0]', '1')
"""
An index read on an all-literal array, paired with the element the deobfuscator folds it to.
"""

_ALIAS_PROPERTY = ('globalThis.parseInt', 'parseInt')
"""
A property read on an alias of the global object, paired with the name the deobfuscator folds it to.
"""

_FOLDABLE_READS = [
    _ARRAY_INDEX,
    _ALIAS_PROPERTY,
]

_PARENTHESIZED_WRITE = 'console.log((TARGET) = 9);'

_ESTABLISHED_GLOBAL = inspect.cleandoc("""
    zz = 1;
    console.log(zz);
""")
"""
A prologue that defines the global `zz` and reads it, so that a later `globalThis.zz` is a read the
deobfuscator is licensed to collapse to the bare name: the write establishing `zz` has run by then.
"""

_LOCAL_ALIAS_WRITE = inspect.cleandoc("""
    var g = globalThis;
    console.log(g.parseInt = 9);
""")

_READS_OF_THE_SAME_ACCESS = [
    (
        'console.log([1, 2, 3][0]);',
        'console.log(1);',
    ),
    (
        'console.log(globalThis.parseInt);',
        'console.log(parseInt);',
    ),
]

_READS_INSIDE_A_WRITE_TARGET = [
    (
        'console.log([1, 2, 3][0].x = 5);',
        'console.log((1).x = 5);',
    ),
    (
        'console.log(globalThis.parseInt.x = 5);',
        'console.log(parseInt.x = 5);',
    ),
    (
        'console.log([1, 2, 3][[0, 1][0]] = 9);',
        'console.log([1, 2, 3][0] = 9);',
    ),
    (
        'console.log({ p: [1, 2, 3][0] } = { p: [4, 5, 6][1] });',
        'console.log({ p: [1, 2, 3][0] } = { p: 5 });',
    ),
]

_WRITES_INTO_AN_ARRAY_LITERAL_FOLDED_WHOLE = {
    'assignment': 'console.log(9);',
    'compound assignment': 'console.log(6);',
    'postfix increment': 'console.log(1);',
    'prefix decrement': 'console.log(0);',
    'delete': 'console.log(true);',
    'array pattern': 'console.log([9]);',
    'array pattern with default': 'console.log([]);',
    'object pattern': 'console.log({ p: 9 });',
    'nested pattern': 'console.log([{ p: 9 }]);',
    'for-in head': 'console.log("in");',
    'for-of head': 'console.log("of");',
}

_WRITES_FOLDED_WHOLE = {
    _ARRAY_INDEX[0]: _WRITES_INTO_AN_ARRAY_LITERAL_FOLDED_WHOLE,
}

_WRITES_A_READ_STANDS_IN_FOLDED_WHOLE = {
    'console.log([1, 2, 3][0].x = 5);': 'console.log(5);',
    'console.log([1, 2, 3][[0, 1][0]] = 9);': 'console.log(9);',
    'console.log({ p: [1, 2, 3][0] } = { p: [4, 5, 6][1] });': 'console.log({ p: 5 });',
}


def _in_position(template: str, target: str) -> str:
    return template.replace('TARGET', target)


def _deobfuscate(source: str) -> str:
    return source.encode('utf8') | djs(strict=True) | str


def _rewritten_snippets() -> list[str]:
    snippets = [_in_position(_PARENTHESIZED_WRITE, target) for target, _ in _FOLDABLE_READS]
    snippets.extend(source for source, _ in _READS_OF_THE_SAME_ACCESS)
    snippets.extend(source for source, _ in _READS_INSIDE_A_WRITE_TARGET)
    snippets.append(_LOCAL_ALIAS_WRITE)
    snippets.extend(
        _in_position(template, target)
        for target in _WRITES_FOLDED_WHOLE
        for _, template in WRITE_POSITIONS
    )
    return snippets


class TestMemberWriteTargets(TestBase):
    """
    Every snippet here is spelled as the deobfuscator prints code, so a snippet it leaves alone
    comes back as the same text.
    """

    def test_a_write_target_survives_deobfuscation_verbatim_unless_the_whole_write_folds(self):
        for target, _ in _FOLDABLE_READS:
            folded_whole = _WRITES_FOLDED_WHOLE.get(target, {})
            for position, template in WRITE_POSITIONS:
                source = _in_position(template, target)
                with self.subTest(target=target, position=position):
                    self.assertIn(_deobfuscate(source), (source, folded_whole.get(position, source)))

    @opportunity
    def test_a_write_into_an_array_literal_folds_to_the_value_it_hands_on(self):
        target, _ = _ARRAY_INDEX
        self.assertEqual(
            {
                position: _deobfuscate(_in_position(template, target))
                for position, template in WRITE_POSITIONS
            },
            _WRITES_INTO_AN_ARRAY_LITERAL_FOLDED_WHOLE,
        )

    def test_a_write_to_an_established_global_through_an_alias_survives_verbatim(self):
        for position, template in WRITE_POSITIONS:
            written = _in_position(template, 'globalThis.zz')
            source = F'{_ESTABLISHED_GLOBAL}\n{written}'
            with self.subTest(position=position):
                self.assertEqual(source, _deobfuscate(source))

    def test_a_write_target_reached_through_a_local_alias_of_the_global_object_survives(self):
        self.assertEqual('console.log(globalThis.parseInt = 9);', _deobfuscate(_LOCAL_ALIAS_WRITE))

    def test_parentheses_around_a_write_target_do_not_expose_it_to_the_fold(self):
        for target, _ in _FOLDABLE_READS:
            unwrapped = F'console.log({target} = 9);'
            folded_whole = _WRITES_FOLDED_WHOLE.get(target, {}).get('assignment', unwrapped)
            with self.subTest(target=target):
                self.assertIn(
                    _deobfuscate(_in_position(_PARENTHESIZED_WRITE, target)),
                    (unwrapped, folded_whole),
                )

    def test_the_same_access_in_a_read_position_is_folded(self):
        for source, expected in _READS_OF_THE_SAME_ACCESS:
            with self.subTest(source=source):
                self.assertEqual(expected, _deobfuscate(source))

    def test_a_read_inside_a_write_target_is_folded(self):
        for source, expected in _READS_INSIDE_A_WRITE_TARGET:
            with self.subTest(source=source):
                self.assertIn(
                    _deobfuscate(source),
                    (expected, _WRITES_A_READ_STANDS_IN_FOLDED_WHOLE.get(source, expected)),
                )

    @opportunity
    def test_a_write_holding_a_folded_read_folds_to_the_value_it_hands_on_where_nothing_observes_it(self):
        self.assertEqual(
            {source: _deobfuscate(source) for source in _WRITES_A_READ_STANDS_IN_FOLDED_WHOLE},
            _WRITES_A_READ_STANDS_IN_FOLDED_WHOLE,
        )


@unittest.skipUnless(node_executable() is not None, 'node.js is required')
class TestMemberWriteTargetsAgainstNode(TestBase):

    def test_deobfuscation_preserves_what_node_does(self):
        for source in _rewritten_snippets():
            deobfuscated = _deobfuscate(source)
            with self.subTest(source=source):
                self.assertEqual(
                    behavior(source),
                    behavior(deobfuscated),
                    F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
                )

    def test_folding_an_array_index_write_target_produces_a_program_node_cannot_parse(self):
        """
        `delete` is the one write position that takes any expression: `delete 1` is a program, and
        it answers `true`.
        """
        _, folded = _ARRAY_INDEX
        for position, template in WRITE_POSITIONS:
            with self.subTest(position=position):
                expected = ('true\n', None) if position == 'delete' else ('', 'SyntaxError')
                self.assertEqual(expected, behavior(_in_position(template, folded)))

    def test_folding_a_global_alias_delete_target_is_a_syntax_error_under_strict_mode(self):
        source = inspect.cleandoc("""
            'use strict';
            console.log(delete globalThis.parseInt);
        """)
        folded = inspect.cleandoc("""
            'use strict';
            console.log(delete parseInt);
        """)
        self.assertEqual(('true\n', None), behavior(source))
        self.assertEqual(('', 'SyntaxError'), behavior(folded))
        self.assertEqual(source, _deobfuscate(source))
