"""
A `for` head is not an ordinary expression position. The init slot of `for (INIT; TEST; UPDATE)`
refuses a bare `in`, even in the alternate of a conditional, the body of an arrow or an operand of a
comma; the iterable of a for-of refuses a comma; the target of a for-of refuses anything starting
with the word `let`, while the target of a for-in refuses only `let` followed by `[`. A bracket that
gets an expression past one of these refusals is part of the program even where the tree holds no
node for it.

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

NOT_A_PROGRAM = 'SyntaxError'

FIXTURE = inspect.cleandoc("""
    var log = [];
    var b = {k: 1}, t = {}, a = "p", r, x, k;
    var let = {0: "zero", p: "pea", x: "ex"};
    var async = "async", of = "of";
""")


def _program(loop: str) -> str:
    return F'{FIXTURE}\n{loop}\nconsole.log(JSON.stringify(log));\n'


def node_says(source: str) -> str:
    out, error = behavior(source)
    return error or out.strip()


def printed_from_the_parse(source: str) -> str:
    return JsSynthesizer().convert(JsParser(source).parse())


def printed_without_the_brackets(source: str) -> str:
    tree = JsParser(source).parse()
    while _strip_parentheses(tree):
        pass
    return JsSynthesizer().convert(tree)


class Head(NamedTuple):
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
