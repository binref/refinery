"""
The names at the top of a module of either kind are the file's own: only the file's text can name
them, so a reflection surface elsewhere in the file keeps the names a removal takes only where the
surface can reach them. In a script the same names are globals, which global code names at runtime,
and a surface keeps them all.
"""
from __future__ import annotations

import inspect
import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import deobfuscate_source, node_executable
from test.lib.scripts.js.ledger import (
    FileProgram,
    Reading,
    a_program,
    each_reading_still_prints,
    node_prints_what_each_row_pins,
    printed,
    prints,
)

from refinery.lib.scripts.js.analysis.environment import HostEnvironment
from refinery.lib.scripts.js.options import ExecutionModel


#: Programs with a reflection surface beside names at the top of the file, each with what Node makes
#: of it as a CommonJS file and as an ES module.
A_NAME_AT_THE_TOP_OF_A_FILE_WITH_A_SURFACE = {
    'a dead name at the top of a file with a runtime-keyed global write': FileProgram(
        a_program("""
            var dead = 1; function unused() { return 2; } globalThis[process.argv.length > 99 ? "a" : "b"] = 2; console.log(3);
            """),
        prints('3'),
        prints('3'),
        HostEnvironment.node,
    ),
    'a name a direct eval reads': FileProgram(
        a_program("""
            var keep = 1; eval(process.argv.length > 99 ? "" : "console.log(keep)");
            """),
        prints('1'),
        prints('1'),
        HostEnvironment.node,
    ),
    'a name global code asks about': FileProgram(
        a_program("""
            var x = 1; globalThis[process.argv.length > 99 ? "a" : "b"] = 2; console.log(Function("return typeof x")());
            """),
        prints('undefined'),
        prints('undefined'),
        HostEnvironment.node,
    ),
    'a global property read by a runtime key': FileProgram(
        a_program("""
            globalThis.secret = 1; var k = process.argv.length > 99 ? "x" : "secret"; console.log(globalThis[k]);
            """),
        prints('1'),
        prints('1'),
        HostEnvironment.node,
    ),
    'a global property read by Function': FileProgram(
        a_program("""
            globalThis.secret = 1;globalThis[process.argv.length > 99 ? "a" : "b"] = 2;console.log(Function("return secret")());
            """),
        prints('1'),
        prints('1'),
        HostEnvironment.node,
    ),
    'a global property read by vm': FileProgram(
        a_program("""
            globalThis.secret = 1;globalThis[process.argv.length > 99 ? "a" : "b"] = 2;console.log(require("vm").runInThisContext("secret"));
            """),
        prints('1'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'a dead-looking function a nested direct eval calls': FileProgram(
        a_program("""
            function hidden() { return "h"; } function g(s) { return eval(s); }globalThis[process.argv.length > 99 ? "a" : "b"] = 2;console.log(g(process.argv.length > 99 ? "" : "hidden()"));
            """),
        prints('h'),
        prints('h'),
        HostEnvironment.node,
    ),
    'a global property read through Object.keys': FileProgram(
        a_program("""
            globalThis.secret = 1;globalThis[process.argv.length > 99 ? "a" : "b"] = 2;console.log(Object.keys(globalThis).includes("secret"));
            """),
        prints('true'),
        prints('true'),
        HostEnvironment.node,
    ),
    'a global property a runtime Function reads': FileProgram(
        a_program("""
            globalThis.x = 1; console.log(Function(process.argv.length > 99 ? "" : "return x")());
            """),
        prints('1'),
        prints('1'),
        HostEnvironment.node,
    ),
    'a bare var a direct eval reads': FileProgram(
        a_program("""
            var keep; eval(process.argv.length > 99 ? "" : "console.log(keep)");
            """),
        prints('undefined'),
        prints('undefined'),
        HostEnvironment.node,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestANameAtTheTopOfAFileWithASurfaceStillPrintsWhatItPrints(TestBase):

    def testnode_prints_what_each_row_pins(self):
        node_prints_what_each_row_pins(self, A_NAME_AT_THE_TOP_OF_A_FILE_WITH_A_SURFACE)

    def test_each_program_still_prints_what_it_prints(self):
        each_reading_still_prints(
            self,
            A_NAME_AT_THE_TOP_OF_A_FILE_WITH_A_SURFACE,
            (Reading.COMMONJS, Reading.MODULE, Reading.ES_MODULE),
        )


class TestANameNothingReadsGoesFromTheTopOfAModuleFile(TestBase):

    SOURCE = a_program("""
        var dead = 1;
        function unused() {
          return 2;
        }
        globalThis[process.argv.length > 99 ? "a" : "b"] = 2;
        console.log(3);
        """)

    def test_a_name_nothing_reads_goes_from_a_module_of_either_kind(self):
        for execution in (ExecutionModel.commonjs, ExecutionModel.module):
            with self.subTest(execution.name):
                self.assertEqual(
                    deobfuscate_source(self.SOURCE, execution=execution),
                    inspect.cleandoc("""
                        globalThis[process.argv.length > 99 ? "a" : "b"] = 2;
                        console.log(3);
                        """),
                )

    def test_a_global_of_a_script_stays_where_global_code_may_read_it(self):
        self.assertEqual(deobfuscate_source(self.SOURCE, execution=ExecutionModel.script), printed(self.SOURCE))
