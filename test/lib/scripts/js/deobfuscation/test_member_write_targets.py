from __future__ import annotations

import inspect
import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import behavior, node_executable
from test.lib.scripts.js.analysis.write_positions import WRITE_POSITIONS

from refinery.units.scripting.js import js

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


def _in_position(template: str, target: str) -> str:
    return template.replace('TARGET', target)


def _deobfuscate(source: str) -> str:
    """
    The script the `js` unit emits for *source*, iterated to a fixed point as the unit does.
    """
    return source.encode('utf8') | js() | str


def _rewritten_snippets() -> list[str]:
    """
    Every snippet in this file that deobfuscation changes. The snippets it leaves alone are not
    here: running an unchanged copy of a program to compare it with itself decides nothing.
    """
    snippets = [_in_position(_PARENTHESIZED_WRITE, target) for target, _ in _FOLDABLE_READS]
    snippets.extend(source for source, _ in _READS_OF_THE_SAME_ACCESS)
    snippets.extend(source for source, _ in _READS_INSIDE_A_WRITE_TARGET)
    snippets.append(_LOCAL_ALIAS_WRITE)
    return snippets


class TestMemberWriteTargets(TestBase):
    """
    A member expression the deobfuscator folds as a read — an index into an all-literal array, a
    property of a global object alias — designates a storage location rather than a value when it
    stands in a write position, and folding it there replaces an assignment target with a constant.
    Every snippet below is spelled the way the synthesizer spells it, so the expectation for one
    that may not be folded is that deobfuscation gives it back unchanged.
    """

    def test_a_write_target_survives_deobfuscation_verbatim(self):
        for target, _ in _FOLDABLE_READS:
            for position, template in WRITE_POSITIONS:
                source = _in_position(template, target)
                with self.subTest(target=target, position=position):
                    self.assertEqual(source, _deobfuscate(source))

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
            with self.subTest(target=target):
                self.assertEqual(
                    F'console.log({target} = 9);',
                    _deobfuscate(_in_position(_PARENTHESIZED_WRITE, target)),
                )

    def test_the_same_access_in_a_read_position_is_folded(self):
        for source, expected in _READS_OF_THE_SAME_ACCESS:
            with self.subTest(source=source):
                self.assertEqual(expected, _deobfuscate(source))

    def test_a_read_inside_a_write_target_is_folded(self):
        for source, expected in _READS_INSIDE_A_WRITE_TARGET:
            with self.subTest(source=source):
                self.assertEqual(expected, _deobfuscate(source))


@unittest.skipUnless(node_executable() is not None, 'node.js is required')
class TestMemberWriteTargetsAgainstNode(TestBase):
    """
    Node, not our reading of the specification, decides both halves of the rule: what the program
    the deobfuscator was given does, and what the program the fold would have produced does instead.
    """

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
        The element an index read denotes is not a storage location, so the fold leaves a numeric
        literal where an assignment target must be, and the program is rejected before it runs a
        line. The exception is `delete`, whose operand need not be a reference at all: `delete 1` is
        a legal program that answers what the one it replaces answers, the one write position in
        which Node cannot tell the fold from the original.
        """
        _, folded = _ARRAY_INDEX
        for position, template in WRITE_POSITIONS:
            with self.subTest(position=position):
                expected = ('true\n', None) if position == 'delete' else ('', 'SyntaxError')
                self.assertEqual(expected, behavior(_in_position(template, folded)))

    def test_folding_a_global_alias_delete_target_is_a_syntax_error_under_strict_mode(self):
        """
        A sloppy script writes a global object property and the bare name it folds to the same way,
        so this is where the two come apart: strict mode forbids `delete` of a name and allows
        `delete` of a property.
        """
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
