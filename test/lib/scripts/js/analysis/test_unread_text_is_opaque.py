"""
Source the parser never read — text no grammar reads, and the tail a cut took away — may name
anything that is in scope where it stands. SECURITY: every snippet here is hand-authored and benign,
and nothing is run; the law is what the tool prints for a file it could not read entirely.
"""
from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import (
    deobfuscate_source,
    node_executable,
    node_reads_as_a_program,
)

from refinery.lib.scripts import is_well_formed
from refinery.lib.scripts.js.parser import JsParser


#: A file holding source the parser never read where that source can name what stands around it,
#: mapped to what the deobfuscator prints for it. Node refuses every one of them. The unread span
#: says nothing about what it references, so a parameter list holding one declares names nothing
#: here can see, and a span standing in a body may read or write every binding the body reaches:
#: what a pass may take away is what the file still says nobody can reach, and none of these is.
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

#: The same questions asked of files that hold no unread source, mapped to what the deobfuscator
#: prints for them. Node reads every one of them as a program, and in each the declaration its
#: unread counterpart keeps is taken away or folded into its value: the unread span is the whole of
#: the difference, rather than a shape these files happen not to have.
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


class TestSourceTheParserNeverReadMayNameWhatIsInScopeWhereItStands(TestBase):
    """
    A span of source no grammar read, and a construct the file ended inside, are both text that
    says nothing about what it references. Every binding in scope where one stands may therefore be
    read or written by it, so none of them is provably unused and none of their values is provably
    the value a later read observes.
    """

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
    """
    The control for every file above: with the unread span spelled out as something the grammar
    reads, each declaration the unread version keeps is one nothing names, and it goes.
    """

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
        rows = THE_SAME_FILE_WITH_NOTHING_UNREAD_IN_IT
        self.assertEqual({source: deobfuscate_source(source) for source in rows}, rows)
