"""
A CommonJS file can have Node's `require` load code its text does not hold: a file, a package, or
a built-in module that runs source text. Such code commonly sets up globals, so a `typeof` of a name
the host lacks folds only where no such load may precede it, and the tampering oracle counts every
load as a site. A built-in module that runs no code loads nothing.
"""
from __future__ import annotations

import inspect
import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import (
    deobfuscate_source,
    module_graph_behavior,
    node_executable,
)
from test.lib.scripts.js.ledger import (
    FileProgram,
    Reading,
    a_program,
    each_reading_still_prints,
    node_prints_what_each_row_pins,
    prints,
)

from refinery.lib.scripts.js.analysis.environment import FileKind, HostEnvironment
from refinery.lib.scripts.js.analysis.model import build_semantic_model
from refinery.lib.scripts.js.model import JsCallExpression, JsStringLiteral
from refinery.lib.scripts.js.options import ExecutionModel
from refinery.lib.scripts.js.parser import JsParser


#: Programs that load code through `require` before or after a `typeof` of a name Node lacks, each
#: with what Node makes of it as a CommonJS file and as an ES module.
A_PROGRAM_THAT_LOADS_CODE = {
    'require read as a value': FileProgram(
        a_program("""
            var r = require; r("fs"); console.log(typeof window);
            """),
        prints('undefined'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'a built-in module required': FileProgram(
        a_program("""
            require("fs"); console.log(typeof window);
            """),
        prints('undefined'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'vm under its prefix': FileProgram(
        a_program("""
            require("node:vm").runInThisContext("var window = 1"); console.log(typeof window);
            """),
        prints('number'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'a module that loads files': FileProgram(
        a_program("""
            var M = require("module"); console.log(typeof M._load, typeof define);
            """),
        prints('function undefined'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'typeof inside a function evaluated after the name is created': FileProgram(
        a_program("""
            function f() { return typeof window; } globalThis.window = 1; console.log(f());
            """),
        prints('number'),
        prints('number'),
        HostEnvironment.node,
    ),
    'typeof inside a function evaluated after a required file creates the name': FileProgram(
        a_program("""
            require("fs").writeFileSync(require("path").join(__dirname, "win2.js"), "global.window = 1;"); function f() { return typeof window; } require("./win2.js"); console.log(f());
            """),
        prints('number'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'a require in a function nothing calls': FileProgram(
        a_program("""
            function dummy() {} function dead() { return require("./nothing.js"); } if ("q" in dummy) { dead(); } console.log(typeof window, [1, 2].join("-"));
            """),
        prints('undefined 1-2'),
        prints('undefined 1-2'),
        HostEnvironment.node,
    ),
    'window created by vm': FileProgram(
        a_program("""
            require("vm").runInThisContext("var window = 1"); console.log(typeof window);
            """),
        prints('number'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'window created by a required file': FileProgram(
        a_program("""
            require("fs").writeFileSync(require("path").join(__dirname, "win.js"), "global.window = {};");require("./win.js"); console.log(typeof window);
            """),
        prints('object'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'vm.runInThisContext': FileProgram(
        a_program("""
            require("vm").runInThisContext("var define = 1"); console.log(typeof define);globalThis[process.argv.length > 99 ? "a" : "b"] = 2;
            """),
        prints('number'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'vm.runInThisContext without a surface': FileProgram(
        a_program("""
            require("vm").runInThisContext("var define = 1"); console.log(typeof define);
            """),
        prints('number'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'define created by a required file': FileProgram(
        a_program("""
            require("fs").writeFileSync(require("path").join(__dirname, "amd.js"), "global.define = function (f) { f()._decompress = function () { return 1; }; }; global.define.amd = true;");require("./amd.js"); console.log(typeof define);
            """),
        prints('function'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'window by vm before, a runtime-keyed global write after': FileProgram(
        a_program("""
            require("vm").runInThisContext("var window = 1"); console.log(typeof window);globalThis[process.argv.length > 99 ? "x" : "y"] = 1;
            """),
        prints('number'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'window created by a required file, a runtime-keyed global write after': FileProgram(
        a_program("""
            require("fs").writeFileSync(require("path").join(__dirname, "win.js"), "global.window = {};");require("./win.js"); console.log(typeof window);globalThis[process.argv.length > 99 ? "x" : "y"] = 1;
            """),
        prints('object'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'the same with this surface of the inserted shape': FileProgram(
        a_program("""
            require("fs").writeFileSync(require("path").join(__dirname, "win.js"), "global.window = {};");require("./win.js"); console.log(typeof window); var k = process.argv.length > 99 ? "x" : "y"; this[k] = 1;
            """),
        prints('object'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'a typeof joined into a string after a required file creates the name': FileProgram(
        a_program("""
            require("fs").writeFileSync(require("path").join(__dirname, "win.js"), "global.window = 1;");require("./win.js"); console.log([typeof window].join(""));
            """),
        prints('number'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'a typeof in a callback after a required file creates the name': FileProgram(
        a_program("""
            require("fs").writeFileSync(require("path").join(__dirname, "win.js"), "global.window = 1;");require("./win.js"); console.log(["a"].map(function (x) { return typeof window + x; }).join());
            """),
        prints('numbera'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'a typeof of define joined into a string after a required file creates it': FileProgram(
        a_program("""
            require("fs").writeFileSync(require("path").join(__dirname, "amd.js"), "global.define = function () {};");require("./amd.js"); console.log([typeof define].join(""));
            """),
        prints('function'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'a typeof in a loop before a file is required': FileProgram(
        a_program("""
            require("fs").writeFileSync(require("path").join(__dirname, "win.js"), "global.window = 1;"); for (var i = 0; i < 2; i++) { console.log(typeof window); require("./win.js"); }
            """),
        prints('undefined', 'number'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'a typeof in a function called twice before a file is required': FileProgram(
        a_program("""
            require("fs").writeFileSync(require("path").join(__dirname, "win.js"), "global.window = 1;"); function f() { console.log(typeof window); require("./win.js"); } f(); f();
            """),
        prints('undefined', 'number'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'window created by a file module.require loads': FileProgram(
        a_program("""
            require("fs").writeFileSync(require("path").join(__dirname, "win.js"), "global.window = 1;"); module.require("./win.js"); console.log(typeof window);
            """),
        prints('number'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'a typeof joined into a string before a file is required': FileProgram(
        a_program("""
            require("fs").writeFileSync(require("path").join(__dirname, "win.js"), "global.window = 1;");console.log([typeof window].join("")); require("./win.js"); console.log([typeof window].join(""));
            """),
        prints('undefined', 'number'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAProgramThatLoadsCodeStillPrintsWhatItPrints(TestBase):

    def testnode_prints_what_each_row_pins(self):
        node_prints_what_each_row_pins(self, A_PROGRAM_THAT_LOADS_CODE)

    def test_each_program_still_prints_what_it_prints(self):
        each_reading_still_prints(self, A_PROGRAM_THAT_LOADS_CODE, (Reading.COMMONJS, Reading.MODULE))


class TestTheCallsThatLoadCode(TestBase):

    def _loaded(self, source: str, trust_eval: bool = False) -> list[str | None]:
        ast = JsParser(source).parse()
        model = build_semantic_model(ast, HostEnvironment.node, trust_eval, FileKind.commonjs)
        modules = []
        for site in model.code_load_sites():
            assert isinstance(site, JsCallExpression)
            argument = site.arguments[0]
            modules.append(argument.value if isinstance(argument, JsStringLiteral) else None)
        return modules

    def test_a_builtin_module_that_runs_no_code_loads_none(self):
        self.assertCountEqual(self._loaded('require("fs"); require("path"); require("child_process");'), [])

    def test_a_builtin_module_under_the_node_prefix_loads_none(self):
        self.assertCountEqual(self._loaded('require("node:fs"); require("node:fs/promises"); require("node:test");'), [])

    def test_a_module_node_loads_only_under_its_prefix_is_a_package_without_it(self):
        self.assertCountEqual(self._loaded('require("test"); require("sea");'), ['test', 'sea'])

    def test_a_file_and_a_package_load_code(self):
        self.assertCountEqual(self._loaded('require("./setup.js"); require("lodash");'), ['./setup.js', 'lodash'])

    def test_a_module_named_at_runtime_loads_code(self):
        self.assertCountEqual(self._loaded('var name = process.argv[2]; require(name);'), [None])

    def test_the_builtin_modules_that_run_source_text_load_code(self):
        self.assertCountEqual(
            self._loaded('require("vm"); require("node:vm"); require("module"); require("repl"); require("inspector");'),
            ['vm', 'node:vm', 'module', 'repl', 'inspector'],
        )

    def test_the_trusting_model_assumes_vm_runs_no_code(self):
        self.assertCountEqual(self._loaded('require("vm"); require("node:vm"); require("module");', trust_eval=True), ['module'])

    def test_a_require_the_file_declares_loads_nothing(self):
        self.assertCountEqual(self._loaded('function require(m) { return m; } require("./setup.js");'), [])

    def test_a_require_held_under_another_name_is_not_followed(self):
        self.assertCountEqual(self._loaded('var r = require; r("./setup.js");'), [])

    def test_the_require_of_the_module_object_loads_code(self):
        self.assertCountEqual(self._loaded('module.require("./setup.js"); module.require("fs");'), ['./setup.js'])


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnImportRunsTheFileItNamesBeforeTheModule(TestBase):

    def test_a_typeof_after_an_import_of_a_file_that_creates_the_name_still_prints_what_it_prints(self):
        loader = 'globalThis.window = 1;\n'
        source = 'import "./win.mjs";\nconsole.log(typeof window);\n'
        rewritten = deobfuscate_source(source, execution=ExecutionModel.module, environment=HostEnvironment.node)
        self.assertEqual(
            (
                module_graph_behavior({'win.mjs': loader, 'main.mjs': source}, 'main.mjs'),
                module_graph_behavior({'win.mjs': loader, 'main.mjs': rewritten}, 'main.mjs'),
            ),
            (prints('number'), prints('number')),
        )


class TestATypeofFoldsOnlyBeforeEveryLoad(TestBase):

    def test_a_typeof_before_a_file_is_required_folds_and_one_after_it_stays(self):
        source = a_program("""
            console.log([typeof window].join(""));
            require("./win.js");
            console.log([typeof window].join(""));
            """)
        self.assertEqual(
            deobfuscate_source(source, execution=ExecutionModel.commonjs, environment=HostEnvironment.node),
            inspect.cleandoc("""
                console.log('undefined');
                require("./win.js");
                console.log([typeof window].join(""));
                """),
        )
