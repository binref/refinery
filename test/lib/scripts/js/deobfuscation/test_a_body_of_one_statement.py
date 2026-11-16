"""
SECURITY: Node runs every program here. Each is written by hand; never add one taken from a sample.
"""
from __future__ import annotations

import inspect

from test import TestBase
from test.lib.scripts.js.analysis.differential import deobfuscate_source
from test.lib.scripts.js.ledger import a_program

from refinery.lib.scripts.js.deobfuscation.bodies import JsBareBodyBlocking
from refinery.lib.scripts.js.model import (
    JsBlockStatement,
    JsDoWhileStatement,
    JsForInStatement,
    JsForOfStatement,
    JsForStatement,
    JsIfStatement,
    JsWhileStatement,
    JsWithStatement,
)
from refinery.lib.scripts.js.options import ExecutionModel
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer

_BODIES = (
    'if (c) f();',
    'if (c) f(); else g();',
    'if (a) f(); else if (b) g(); else h();',
    'for (var i = 0; i < 3; i++) f();',
    'for (var k in o) f();',
    'for (var k of o) f();',
    'while (c) f();',
    'do f(); while (c);',
    'with (o) f();',
)


def blocked(source: str) -> str:
    ast = JsParser(source).parse()
    JsBareBodyBlocking().visit(ast)
    return JsSynthesizer().convert(ast)


class TestABodyOfOneStatementIsHeldAsABlock(TestBase):

    def test_each_body_of_one_statement_is_given_the_block_the_printer_writes(self):
        for source in _BODIES:
            with self.subTest(source):
                ast = JsParser(source).parse()
                JsBareBodyBlocking().visit(ast)
                for node in ast.walk():
                    if isinstance(node, JsIfStatement):
                        self.assertIsInstance(node.consequent, JsBlockStatement)
                        if node.alternate is not None:
                            self.assertIsInstance(node.alternate, JsBlockStatement)
                    elif isinstance(node, (
                        JsForStatement,
                        JsForInStatement,
                        JsForOfStatement,
                        JsWhileStatement,
                        JsDoWhileStatement,
                        JsWithStatement,
                    )):
                        self.assertIsInstance(node.body, JsBlockStatement)

    def test_the_written_file_stays_as_it_was(self):
        for source in _BODIES + ('L: f();',):
            with self.subTest(source):
                self.assertEqual(blocked(source), JsSynthesizer().convert(JsParser(source).parse()))

    def test_the_body_of_a_label_stays_the_statement_it_is(self):
        ast = JsParser('L: f();').parse()
        JsBareBodyBlocking().visit(ast)
        self.assertNotIsInstance(
            next(node for node in ast.walk() if hasattr(node, 'label')).body,
            JsBlockStatement,
        )

    def test_a_body_the_parser_could_not_read_stays_as_it_was(self):
        source = 'while (c) @;'
        self.assertEqual(blocked(source), JsSynthesizer().convert(JsParser(source).parse()))


class TestAStatementStandingAsAWholeBodyIsSeenByTheSweeps(TestBase):

    def test_a_dead_declaration_standing_as_a_loop_body_goes_in_the_first_run(self):
        self.assertEqual(
            deobfuscate_source(a_program("""
                for (var i = 0; i < 3; i++) var q;
                console.log(1);
                """)),
            inspect.cleandoc("""
                for (var i = 0; i < 3; i++) {}
                console.log(1);
                """),
        )

    def test_an_empty_statement_standing_as_a_loop_body_goes_in_the_first_run(self):
        self.assertEqual(
            deobfuscate_source(a_program("""
                for (var i = 0; i < 3; i++) ;
                console.log(1);
                """)),
            inspect.cleandoc("""
                for (var i = 0; i < 3; i++) {}
                console.log(1);
                """),
        )


class TestRunningTheDeobfuscatorTwiceDoesNotChangeTheOutput(TestBase):

    def test_each_program_with_a_body_of_one_statement_is_written_as_it_reads_back(self):
        for source in _BODIES + (
            'for (var i = 0; i < 3; i++) var q;\nconsole.log(1);\n',
            'for (var i = 0; i < 3; i++) ;\nconsole.log(1);\n',
            'if (c) var q;\n',
        ):
            with self.subTest(source):
                once = deobfuscate_source(source, execution=ExecutionModel.script)
                self.assertEqual(deobfuscate_source(once, execution=ExecutionModel.script), once)
