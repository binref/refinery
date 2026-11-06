"""
A `for await` head is read only where `await` is the operator: in the body of an `async` function,
arrow or method itself, never in a plain function, arrow, class field or static block, even one
nested in async code, and at the top level of a module but not of a script. The tool does not know
which of the two a file is, so it reads the head at the top level as a module does.

SECURITY: every snippet here is hand-authored and benign, and Node runs it. Nothing from `samples`
may ever be fed to this.
"""
from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import behavior, node_executable
from test.lib.scripts.js.ledger import each_well_formed, prints
from test.lib.scripts.js.test_parameter_grammar import every_one_of, refused

A_FOR_AWAIT_HEAD_OUTSIDE_ASYNC_CODE = [
    'function f() { for await (const x of []) {} }',
    'async function f() { function g() { for await (const x of []) {} } }',
    'async function f() { () => { for await (const x of []) {} }; }',
    'class C { p = () => { for await (const x of []) {} }; }',
    'class C { static { for await (const x of []) {} } }',
    'var o = { m() { for await (const x of []) {} } };',
]

A_FOR_AWAIT_HEAD_IN_ASYNC_CODE = {
    'async function f() { for await (const x of [1]) console.log(x); } f();':
        prints('1'),
    'var f = async () => { for await (const x of [2]) console.log(x); }; f();':
        prints('2'),
    'class C { async m() { for await (const x of [3]) console.log(x); } } new C().m();':
        prints('3'),
    'async function* g() { for await (const x of [4]) yield x; } g().next().then(v => console.log(v.value));':
        prints('4'),
    'class C { static { (async () => { for await (const x of [5]) console.log(x); })(); } }':
        prints('5'),
}

A_FOR_AWAIT_HEAD_AT_THE_TOP_LEVEL = 'for await (const x of [6]) console.log(x);'


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestWhatNodeMakesOfAForAwaitHead(TestBase):

    def test_node_refuses_the_head_outside_async_code_under_either_goal(self):
        rows = A_FOR_AWAIT_HEAD_OUTSIDE_ASYNC_CODE
        self.assertEqual(refused(rows), every_one_of(rows, True))
        self.assertEqual(
            {source: behavior(source, module=True) for source in rows},
            {source: ('', 'SyntaxError') for source in rows},
        )

    def test_node_prints_what_each_file_with_the_head_in_async_code_is_recorded_as_printing(self):
        rows = A_FOR_AWAIT_HEAD_IN_ASYNC_CODE
        self.assertEqual({source: behavior(source) for source in rows}, rows)

    def test_node_reads_the_head_at_the_top_level_as_a_module_alone(self):
        source = A_FOR_AWAIT_HEAD_AT_THE_TOP_LEVEL
        self.assertEqual(
            (refused([source])[source], behavior(source, module=True)),
            (True, prints('6')),
        )


class TestTheVerdictAnswersAsNodeDoes(TestBase):

    def test_the_head_outside_async_code_is_no_program(self):
        rows = A_FOR_AWAIT_HEAD_OUTSIDE_ASYNC_CODE
        self.assertEqual(each_well_formed(rows), every_one_of(rows, False))

    def test_the_head_in_async_code_is_a_program(self):
        rows = A_FOR_AWAIT_HEAD_IN_ASYNC_CODE
        self.assertEqual(each_well_formed(rows), every_one_of(rows, True))

    def test_the_head_at_the_top_level_is_read_as_the_module_reads_it(self):
        source = A_FOR_AWAIT_HEAD_AT_THE_TOP_LEVEL
        self.assertEqual(each_well_formed([source]), {source: True})
