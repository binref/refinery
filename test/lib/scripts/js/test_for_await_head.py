"""
Where a `for await` head is read, and whether the tool reads it where the language does.

The head stands where `await` is the operator: the body of an `async` function, arrow or method.
A plain function, a non-async arrow, a class field initializer and a static block have no reading
for it, whatever encloses them, and neither goal symbol changes that. The top level of a file is
the one place the goal decides: a module reads the head there and a script refuses it, and the
parser, which does not know the goal, reads it.

Node decides every expectation here. The question put to it is whether it reads a text at all, as
a script and as a module, and the law is that `refinery.lib.scripts.is_well_formed` answers as
both readings do below the top level and as the module reading does at it.

SECURITY: every snippet here is hand-authored and benign, and running it is what makes the engine
the oracle. Nothing from `samples` may ever be fed to this.
"""
from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import behavior, node_executable
from test.lib.scripts.js.ledger import each_well_formed, prints
from test.lib.scripts.js.test_parameter_grammar import every_one_of, refused

#: A `for await` head below the top level of a file, where `await` is not the operator. Node
#: refuses each as a script and as a module.
A_FOR_AWAIT_HEAD_OUTSIDE_ASYNC_CODE = [
    'function f() { for await (const x of []) {} }',
    'async function f() { function g() { for await (const x of []) {} } }',
    'async function f() { () => { for await (const x of []) {} }; }',
    'class C { p = () => { for await (const x of []) {} }; }',
    'class C { static { for await (const x of []) {} } }',
    'var o = { m() { for await (const x of []) {} } };',
]

#: The head where `await` is the operator, mapped to what Node prints for each file.
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

#: The head at the top level of a file, which Node refuses as a script and reads as a module.
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
