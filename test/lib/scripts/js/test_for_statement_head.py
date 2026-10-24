"""
The head of a `for` loop is not an ordinary expression position, and what the tool prints there has
to be a program that still means what the source did.

A head comes in three shapes — `for (INIT; TEST; UPDATE)`, `for (TARGET in OBJECT)` and
`for (TARGET of ITERABLE)` — and each slot claims a word or an operator for itself. The init slot
reads a bare `in` as the start of a for-in and refuses it, all the way down through a conditional's
alternate, an arrow's expression body and a comma; the for-of iterable slot is a single
`AssignmentExpression` and refuses a comma; the for-of target slot refuses anything opening with the
word `let`, where the for-in target only refuses `let` immediately before a bracket. The three
refusals are not each other's and none of them is the one an ordinary statement makes: a statement
refuses a leading `{` and a leading `function`, which every one of these slots accepts.

The brackets that get a refused expression into a slot are therefore load-bearing text, and they are
not necessarily nodes: a pass that folds an expression into the slot a bracket used to occupy leaves
a tree that has to be printed with brackets nothing in it holds. So the law here is not that the
brackets come back, it is that the output is a program that does what the input did, and it is
checked over three ways of getting from a source to an output — printing what was parsed, printing
after every bracket in the tree is replaced by what it holds, and printing what the deobfuscation
passes leave behind.

Node.js decides all of it. Every head is recorded together with what V8 prints for it and with a
second spelling of the same head, one bracket added or taken away, and what V8 prints for that one:
where the two differ the bracket carries meaning, and where they agree the slot tolerates it either
way. Both spellings are re-measured by the tests, so a row cannot go stale into a claim nothing
checks.

`HEADS` is the whole corpus and the law below is quantified over all of it. Seven of these rows were
a second table the law had to leave out, each one a head whose `in` the parser read under a ban the
grammar had already lifted; they are ordinary rows now.

SECURITY: the snippets here are hand-authored and benign, and running them is what makes the engine
the oracle. Nothing from `samples` may ever be fed to this.
"""
from __future__ import annotations

import inspect
import unittest

from typing import NamedTuple

from test import TestBase
from test.lib.scripts.js.analysis.differential import (
    behavior,
    deobfuscate_source,
    node_executable,
)
from test.lib.scripts.js.test_fidelity import _strip_parentheses

from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer

#: What Node.js says about a text it does not read as a program at all. The law below is quantified
#: over programs, so this is what a respelling says and never what a head says.
NOT_A_PROGRAM = 'SyntaxError'

#: The names every snippet shares, so that a row is the loop head it is about and nothing else. The
#: values are chosen to make each head observable: `let` holds the three properties the heads that
#: use it read, and `b` holds the one key the `in` operator asks for.
FIXTURE = inspect.cleandoc("""
    var log = [];
    var b = {k: 1}, t = {}, a = "p", r, x, k;
    var let = {0: "zero", p: "pea", x: "ex"};
    var async = "async", of = "of";
""")


def _program(loop: str) -> str:
    return F'{FIXTURE}\n{loop}\nconsole.log(JSON.stringify(log));\n'


def node_says(source: str) -> str:
    """
    What Node.js makes of *source*: the standard output it produced, or the name of the error that
    stopped it. Every snippet here ends by printing the log it built as a JSON array, so the two
    kinds of answer cannot be mistaken for one another.
    """
    out, error = behavior(source)
    return error or out.strip()


def printed_from_the_parse(source: str) -> str:
    """
    What this project prints for the tree its parser built from *source*.
    """
    return JsSynthesizer().convert(JsParser(source).parse())


def printed_without_the_brackets(source: str) -> str:
    """
    What this project prints once every bracket of the parse of *source* has been replaced by what
    it holds, which is the tree a pass folding into a bracketed slot leaves behind.
    """
    tree = JsParser(source).parse()
    while _strip_parentheses(tree):
        pass
    return JsSynthesizer().convert(tree)


class Head(NamedTuple):
    """
    A loop head and what the program around it prints, together with the same head respelled by one
    bracket and what that prints. The respelling is a substitution rather than a second program so
    that the two can differ nowhere but in the head.
    """
    loop: str
    prints: str
    respelling: tuple[str, str]
    respelling_prints: str

    @property
    def source(self) -> str:
        return _program(self.loop)

    @property
    def respelled(self) -> str:
        return _program(self.loop.replace(*self.respelling))


HEADS = [
    Head(
        'for (r = ("k" in b); r; r = false) log.push(r);',
        '[true]',
        ('("k" in b)', '"k" in b'),
        NOT_A_PROGRAM,
    ),
    Head(
        'for (var v = ("k" in b); v; v = false) log.push(v);',
        '[true]',
        ('("k" in b)', '"k" in b'),
        NOT_A_PROGRAM,
    ),
    Head(
        'for (("k" in b), log.push("ran"); false; ) ;',
        '["ran"]',
        ('("k" in b)', '"k" in b'),
        NOT_A_PROGRAM,
    ),
    Head(
        'for (q => ("k" in b); log.length < 1; ) log.push("ran");',
        '["ran"]',
        ('("k" in b)', '"k" in b'),
        NOT_A_PROGRAM,
    ),
    Head(
        'for (false ? 0 : ("k" in b); log.length < 1; ) log.push("ran");',
        '["ran"]',
        ('("k" in b)', '"k" in b'),
        NOT_A_PROGRAM,
    ),
    Head(
        'for (log.push("k" in b); log.length < 2; ) log.push("ran");',
        '[true,"ran"]',
        ('"k" in b', '("k" in b)'),
        '[true,"ran"]',
    ),
    Head(
        'for (var n = 0; n < 1 && "k" in b; n++, "k" in b) log.push(n);',
        '[0]',
        ('n < 1 && "k" in b', 'n < 1 && ("k" in b)'),
        '[0]',
    ),
    Head(
        'for ((let)[0]; log.length < 1; ) log.push(let[0]);',
        '["zero"]',
        ('(let)[0]', 'let[0]'),
        NOT_A_PROGRAM,
    ),
    Head(
        'for ({p: r} = {p: "set"}; log.length < 1; ) log.push(r);',
        '["set"]',
        ('{p: r} = {p: "set"}', '({p: r} = {p: "set"})'),
        '["set"]',
    ),
    Head(
        'for ((let)[a] in {q: 1}) log.push(let[a], a);',
        '["q","p"]',
        ('(let)[a]', 'let[a]'),
        '[null,"q"]',
    ),
    Head(
        'for (k in ({a: 1}, {q: 2})) log.push(k);',
        '["q"]',
        ('({a: 1}, {q: 2})', '{a: 1}, {q: 2}'),
        '["q"]',
    ),
    Head(
        'for (let in {q: 1}) log.push(let);',
        '["q"]',
        ('let in', '(let) in'),
        '["q"]',
    ),
    Head(
        'for (let.x in {q: 1}) log.push(let.x);',
        '["q"]',
        ('let.x in', '(let).x in'),
        '["q"]',
    ),
    Head(
        'for ([r] in {q: 1}) log.push(r);',
        '["q"]',
        ('[r] in', '([r]) in'),
        NOT_A_PROGRAM,
    ),
    Head(
        'for (var v = "init" in {q: 1}) log.push(v);',
        '["q"]',
        ('"init" in {q: 1}', '("init" in {q: 1})'),
        NOT_A_PROGRAM,
    ),
    Head(
        'for (x of ([1, 2], [3, 4])) log.push(x);',
        '[3,4]',
        ('([1, 2], [3, 4])', '[1, 2], [3, 4]'),
        NOT_A_PROGRAM,
    ),
    Head(
        'for ((let) of [42]) log.push(let);',
        '[42]',
        ('((let) of', '(let of'),
        NOT_A_PROGRAM,
    ),
    Head(
        'for ((let).x of [42]) log.push(let.x);',
        '[42]',
        ('(let).x', 'let.x'),
        NOT_A_PROGRAM,
    ),
    Head(
        'for ((async) of [42]) log.push(async);',
        '[42]',
        ('((async) of', '(async of'),
        NOT_A_PROGRAM,
    ),
    Head(
        'for (of of [42]) log.push(of);',
        '[42]',
        ('of of', '(of) of'),
        '[42]',
    ),
    Head(
        'for ([r, x] of [[1, 2]]) log.push(r, x);',
        '[1,2]',
        ('[r, x] of', '([r, x]) of'),
        NOT_A_PROGRAM,
    ),
    Head(
        'for (x of r = [7]) log.push(x, r[0]);',
        '[7,7]',
        ('of r = [7]', 'of (r = [7])'),
        '[7,7]',
    ),
    Head(
        'for (true ? "k" in b : 0; log.length < 1; ) log.push("ran");',
        '["ran"]',
        ('"k" in b', '("k" in b)'),
        '["ran"]',
    ),
    Head(
        'for (r = new Array("k" in b); log.length < 1; ) log.push(r.length);',
        '[1]',
        ('"k" in b', '("k" in b)'),
        '[1]',
    ),
    Head(
        'for (function () { return "k" in b; }; log.length < 1; ) log.push("ran");',
        '["ran"]',
        ('"k" in b', '("k" in b)'),
        '["ran"]',
    ),
    Head(
        'for (q => { return "k" in b; }; log.length < 1; ) log.push("ran");',
        '["ran"]',
        ('"k" in b', '("k" in b)'),
        '["ran"]',
    ),
    Head(
        'for (`${"k" in b}`; log.length < 1; ) log.push("ran");',
        '["ran"]',
        ('"k" in b', '("k" in b)'),
        '["ran"]',
    ),
    Head(
        'for (t["k" in b] = "set"; log.length < 1; ) log.push(t[true]);',
        '["set"]',
        ('"k" in b', '("k" in b)'),
        '["set"]',
    ),
    Head(
        'for (t["k" in b] in {q: 1}) log.push(t[true]);',
        '["q"]',
        ('"k" in b', '("k" in b)'),
        '["q"]',
    ),
]

class TestJsForHeadCorpus(TestBase):
    """
    What the corpus claims about itself, checked without an engine. A row that is not a program, or
    whose two spellings differ somewhere other than the head, would leave the law below asserting
    something other than what it says it asserts.
    """

    def test_every_head_is_recorded_as_a_program(self):
        for head in HEADS:
            with self.subTest(loop=head.loop):
                self.assertNotEqual(head.prints, NOT_A_PROGRAM)

    def test_every_respelling_moves_one_bracket_and_changes_nothing_else(self):
        for head in HEADS:
            with self.subTest(loop=head.loop):
                self.assertEqual(head.loop.count(head.respelling[0]), 1)
                self.assertNotEqual(head.respelled, head.source)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestJsForHeadSurvivesPrinting(TestBase):
    """
    The law: whatever the source said, what this project prints is a program that does the same
    thing. Three routes reach the printer with different trees — the one the parser built, that one
    with every bracket replaced by what it holds, and the one the deobfuscation passes left — and
    the engine answers for all three.
    """

    def test_node_reads_both_spellings_of_every_head_as_the_corpus_records_them(self):
        for head in HEADS:
            with self.subTest(loop=head.loop):
                self.assertEqual(node_says(head.source), head.prints)
                self.assertEqual(node_says(head.respelled), head.respelling_prints)

    def test_printing_a_parsed_head_keeps_what_it_does(self):
        for head in HEADS:
            with self.subTest(loop=head.loop):
                printed = printed_from_the_parse(head.source)
                self.assertEqual(node_says(printed), head.prints, printed)

    def test_printing_a_head_whose_brackets_left_the_tree_keeps_what_it_does(self):
        for head in HEADS:
            with self.subTest(loop=head.loop):
                printed = printed_without_the_brackets(head.source)
                self.assertEqual(node_says(printed), head.prints, printed)

    def test_deobfuscating_a_head_keeps_what_it_does(self):
        for head in HEADS:
            with self.subTest(loop=head.loop):
                printed = deobfuscate_source(head.source)
                self.assertEqual(node_says(printed), head.prints, printed)
