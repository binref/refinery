"""
SECURITY: every snippet here is hand-authored and benign, and none is run: Node is only asked
whether it reads one as a program.
"""
from __future__ import annotations

import unittest

from test import TestBase, opportunity
from test.lib.scripts.js.analysis.differential import (
    deobfuscate_source,
    node_executable,
    node_reads_as_a_program,
)

from refinery.lib.scripts import is_well_formed
from refinery.lib.scripts.js.parser import JsParser


A_FILE_HOLDING_SOURCE_THE_PARSER_NEVER_READ = {
    'var a = 1; function f(a b) { return a; } console.log(f(1));': (
        'var a = 1;\nfunction f(a b) {\n  return a;\n}\nconsole.log(f(1));'
    ),
    'var a = 1; function f({a b}) { return a; } console.log(f(1));': (
        'var a = 1;\nfunction f({ a b }) {\n  return a;\n}\nconsole.log(f(1));'
    ),
    'var v = 7;\nconsole.log(v q);': 'var v = 7;\nconsole.log(v q);',
    'function helper() { return 42; }\nconsole.log(helper() q);': (
        'function helper() {\n  return 42;\n}\nconsole.log(helper() q);'
    ),
    'var x = 1; x = y[a b]; console.log(x);': 'var x = 1;\nx = y[a b];\nconsole.log(x);',
    'function f() { var x = 1; x = y[a b]; return x; } console.log(f());': (
        'function f() {\n  var x = 1;\n  x = y[a b];\n  return x;\n}\nconsole.log(f());'
    ),
    'var e = 1;\ntry { g(); } catch (e f) { console.log(e); }': (
        'var e = 1;\ntry { g(); } catch (e f) { console.log(e); }'
    ),
    'var dead = 1;\nconsole.log(2);\nfunction beacon() { fetch("http://x.invalid");': (
        'var dead = 1;\nconsole.log(2);\nfunction beacon() {\n  fetch("http://x.invalid");'
    ),
}

THE_SAME_FILE_WITH_NOTHING_UNREAD_IN_IT = {
    'var a = 1; function f(b) { return a; } console.log(f(1));': 'console.log(1);',
    'var a = 1; function f({b}) { return a; } console.log(f(1));': (
        'function f({ b }) {\n  return 1;\n}\nconsole.log(f(1));'
    ),
    'var v = 7;\nconsole.log(v);': 'console.log(7);',
    'function helper() { return 42; }\nconsole.log(helper());': 'console.log(42);',
    'var x = 1; y[a]; console.log(x);': 'y[a];\nconsole.log(1);',
    'function f() { var x = 1; x = y[a]; return x; } console.log(f());': (
        'function f() {\n  var x;\n  x = y[a];\n  return x;\n}\nconsole.log(f());'
    ),
    'var e = 1;\ntry { g(); } catch (e) { console.log(e); }': (
        'try {\n  g();\n} catch (e) {\n  console.log(e);\n}'
    ),
    'var dead = 1;\nconsole.log(2);\nfunction beacon() { fetch("http://x.invalid"); }': (
        'console.log(2);'
    ),
}

THE_SAME_FILE_WITH_ITS_FUNCTION_INLINED = {
    'var a = 1; function f({b}) { return a; } console.log(f(1));': 'console.log(1);',
    'function f() { var x = 1; x = y[a]; return x; } console.log(f());': 'console.log(y[a]);',
}


class TestSourceTheParserNeverReadMayNameWhatIsInScopeWhereItStands(TestBase):

    def test_no_file_is_a_program(self):
        rows = A_FILE_HOLDING_SOURCE_THE_PARSER_NEVER_READ
        self.assertEqual(
            {source: is_well_formed(JsParser(source).parse()) for source in rows},
            {source: False for source in rows},
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_refuses_every_file(self):
        rows = A_FILE_HOLDING_SOURCE_THE_PARSER_NEVER_READ
        self.assertEqual(
            {source: node_reads_as_a_program(source) for source in rows},
            {source: False for source in rows},
        )

    def test_nothing_the_unread_source_could_name_is_taken_away(self):
        rows = A_FILE_HOLDING_SOURCE_THE_PARSER_NEVER_READ
        self.assertEqual({source: deobfuscate_source(source) for source in rows}, rows)

    def test_the_print_is_a_fixpoint(self):
        prints = A_FILE_HOLDING_SOURCE_THE_PARSER_NEVER_READ.values()
        self.assertEqual(
            {answer: deobfuscate_source(answer) for answer in prints},
            {answer: answer for answer in prints},
        )


class TestTheSameFileWithNothingUnreadInItLosesWhatNothingReads(TestBase):

    def test_every_file_is_a_program(self):
        rows = THE_SAME_FILE_WITH_NOTHING_UNREAD_IN_IT
        self.assertEqual(
            {source: is_well_formed(JsParser(source).parse()) for source in rows},
            {source: True for source in rows},
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_reads_every_file_as_a_program(self):
        rows = THE_SAME_FILE_WITH_NOTHING_UNREAD_IN_IT
        self.assertEqual(
            {source: node_reads_as_a_program(source) for source in rows},
            {source: True for source in rows},
        )

    def test_what_nothing_reads_is_taken_away(self):
        for source, expected in THE_SAME_FILE_WITH_NOTHING_UNREAD_IN_IT.items():
            inlined = THE_SAME_FILE_WITH_ITS_FUNCTION_INLINED.get(source, expected)
            with self.subTest(source=source):
                self.assertIn(deobfuscate_source(source), (expected, inlined))

    @opportunity
    def test_the_function_called_once_is_inlined(self):
        rows = THE_SAME_FILE_WITH_ITS_FUNCTION_INLINED
        self.assertEqual({source: deobfuscate_source(source) for source in rows}, rows)
