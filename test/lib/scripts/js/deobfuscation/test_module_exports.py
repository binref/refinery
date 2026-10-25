"""
A CommonJS file hands what it stores in `module.exports` to the code that loads it. `refinery.djs`
assumes no code loads the input unless `-l` says otherwise, so a store that replaces
`module.exports` in a file that never reads `module` back is read by nothing and goes. Every other
store into the module objects stays, and so does the store wherever the file reads its exports back
or the file may be an ES module.
"""
from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import deobfuscate_source, node_executable
from test.lib.scripts.js.ledger import (
    NL,
    FileProgram,
    Reading,
    a_program,
    each_reading_still_prints,
    node_prints_what_each_row_pins,
    printed,
    prints,
    wontfix,
)

from refinery.lib.scripts.js.analysis.environment import HostEnvironment
from refinery.lib.scripts.js.deobfuscation import deobfuscate
from refinery.lib.scripts.js.options import ExecutionModel
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer


def _loaded_by_other_files(source: str) -> str:
    ast = JsParser(source).parse()
    deobfuscate(
        ast,
        execution=ExecutionModel.commonjs,
        environment=HostEnvironment.node,
        loaded_by_other_files=True,
    )
    return JsSynthesizer().convert(ast)


#: Programs that store into the module objects, read what they stored back, or change the objects
#: the stores go through, each with what Node makes of it as a CommonJS file and as an ES module.
A_STORE_INTO_THE_MODULE_OBJECTS = {
    'a store into exports nothing reads': FileProgram(
        a_program("""
            exports.a = 1; module.exports.b = 2; console.log(3);
            """),
        prints('3'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'a store read back through module.exports': FileProgram(
        a_program("""
            exports.a = 1; console.log(JSON.stringify(module.exports));
            """),
        prints('{"a":1}'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'read back through this': FileProgram(
        a_program("""
            exports.a = 1; console.log(this.a);
            """),
        prints('1'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'read back through arguments': FileProgram(
        a_program("""
            exports.a = 1; console.log(arguments[0].a);
            """),
        prints('1'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'read back through require.cache': FileProgram(
        a_program("""
            exports.a = 1; console.log(require.cache[__filename].exports.a);
            """),
        prints('1'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'read back through require.main': FileProgram(
        a_program("""
            exports.a = 1; console.log(require.main.exports.a);
            """),
        prints('1'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'exports held under a second name': FileProgram(
        a_program("""
            var e = exports; e.a = 1; console.log(exports.a);
            """),
        prints('1'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'read back in a function': FileProgram(
        a_program("""
            function f() { return exports.a; } exports.a = 1; console.log(f());
            """),
        prints('1'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'a replaced export written through module.exports': FileProgram(
        a_program("""
            var o = {}; module.exports = o; module.exports.k = 1; console.log(o.k);
            """),
        prints('1'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'a setter on the replaced export': FileProgram(
        a_program("""
            module.exports = { set a(v) { console.log("set", v); } }; module.exports.a = 5; console.log(2);
            """),
        prints('set 5', '2'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'a property defined on exports': FileProgram(
        a_program("""
            Object.defineProperty(exports, "a", { set: function (v) { console.log("set", v); } }); exports.a = 5;
            """),
        prints('set 5'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'a store whose value has an effect': FileProgram(
        a_program("""
            exports.a = (console.log("effect"), 1); console.log(2);
            """),
        prints('effect', '2'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'a store under a typeof guard': FileProgram(
        a_program("""
            "undefined" != typeof module && null != module ? module.exports = { v: 1 } : false; console.log(2);
            """),
        prints('2'),
        prints('2'),
        HostEnvironment.node,
    ),
    'a bare store in a file that may be an ES module': FileProgram(
        a_program("""
            module.exports = 1; console.log(2);
            """),
        prints('2'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'the module object replaced by the file': FileProgram(
        a_program("""
            module = { set exports(v) { console.log("set"); } }; module.exports = 1;
            """),
        prints('set'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'module read back after the store': FileProgram(
        a_program("""
            module.exports = 1; console.log(module.exports);
            """),
        prints('1'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'the wrapper arguments read': FileProgram(
        a_program("""
            module.exports = { a: 1 }; console.log(arguments[2].exports.a);
            """),
        prints('1'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'the wrapper reached through caller': FileProgram(
        a_program("""
            function f() { return f.caller.arguments[2].exports; } module.exports = 5; console.log(f());
            """),
        prints('5'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'module named in a with body': FileProgram(
        a_program("""
            with ({}) { module.exports = 1; } console.log(typeof module.exports);
            """),
        prints('number'),
        ('', 'SyntaxError'),
        HostEnvironment.node,
    ),
    'a direct eval reads module': FileProgram(
        a_program("""
            module.exports = 7; eval(process.argv.length > 99 ? "" : "console.log(module.exports)");
            """),
        prints('7'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'a function that only replaces the exports, called twice': FileProgram(
        a_program("""
            function init(v) { module.exports = v; } init(1); init(2); console.log(3);
            """),
        prints('3'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'the store in a sequence': FileProgram(
        a_program("""
            console.log((module.exports = 1, 2));
            """),
        prints('2'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'the value of the store used': FileProgram(
        a_program("""
            var x = (module.exports = { a: 1 }); console.log(x.a);
            """),
        prints('1'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'a store into the replaced exports': FileProgram(
        a_program("""
            module.exports = {}; module.exports.a = 2; console.log(3);
            """),
        prints('3'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'module frozen in a strict file': FileProgram(
        a_program("""
            "use strict"; Object.freeze(module); try { module.exports = 1; console.log("stored"); } catch (e) { console.log(e.constructor.name); }
            """),
        (F'TypeError{NL}', 'TypeError'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'a function exported and never called': FileProgram(
        a_program("""
            module.exports = function () { console.log("called"); }; console.log(1);
            """),
        prints('1'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'module under a second name': FileProgram(
        a_program("""
            var m = module; m.exports = 1; console.log(m.exports);
            """),
        prints('1'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'the store under a typeof guard': FileProgram(
        a_program("""
            typeof module === "object" && (module.exports = { a: 1 }); console.log(2);
            """),
        prints('2'),
        prints('2'),
        HostEnvironment.node,
    ),
    'module redefined by defineProperty': FileProgram(
        a_program("""
            Object.defineProperty(module, "exports", { set: function (v) { console.log("set", v); } }); module.exports = 1;
            """),
        prints('set 1'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'a store into exports inside a function called once': FileProgram(
        a_program("""
            function init() { exports.a = 1; } init(); console.log(2);
            """),
        prints('2'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'a store into exports inside a sequence': FileProgram(
        a_program("""
            console.log((exports.a = 1, 2));
            """),
        prints('2'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'a store into exports inside a function called twice': FileProgram(
        a_program("""
            function init(v) { exports.a = v; } init(1); init(2); console.log(3);
            """),
        prints('3'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'read back through a require of the file itself': FileProgram(
        a_program("""
            exports.a = 1; console.log(require(__filename).a);
            """),
        prints('1'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'read back through process.mainModule': FileProgram(
        a_program("""
            exports.a = 1; console.log(process.mainModule.exports.a);
            """),
        prints('1'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'read back through the module cache of require("module")': FileProgram(
        a_program("""
            exports.a = 1; console.log(require("module")._cache[__filename].exports.a);
            """),
        prints('1'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'a setter installed through a store to __proto__': FileProgram(
        a_program("""
            exports.__proto__ = { set k(v) { console.log("set", v); } }; exports.k = 1;
            """),
        prints('set 1'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'a setter on Object.prototype': FileProgram(
        a_program("""
            Object.defineProperty(Object.prototype, "k", { set: function (v) { console.log("set", v); } }); exports.k = 1;
            """),
        prints('set 1'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'a setter on Object.prototype, with a statement after the store': FileProgram(
        a_program("""
            Object.defineProperty(Object.prototype, "k", { set: function (v) { console.log("set", v); } }); exports.k = 1; console.log(2);
            """),
        prints('set 1', '2'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'a setter on the prototype of every module': FileProgram(
        a_program("""
            Object.defineProperty(require("module").prototype, "k", { set: function (v) { console.log("set", v); } }); module.k = 1;
            """),
        prints('set 1'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'a setter on the prototype of every module, with a statement after the store': FileProgram(
        a_program("""
            Object.defineProperty(require("module").prototype, "k", { set: function (v) { console.log("set", v); } }); module.k = 1; console.log(2);
            """),
        prints('set 1', '2'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'read back through the this of a top-level arrow': FileProgram(
        a_program("""
            exports.a = 1; console.log((() => this.a)());
            """),
        prints('1'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'read back by a dynamic import of the file': FileProgram(
        a_program("""
            exports.a = 1; import(require("url").pathToFileURL(__filename).href).then(function (m) { console.log(m.default.a); });
            """),
        prints('1'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'a setter on Object.prototype through __proto__ of a fresh object': FileProgram(
        a_program("""
            ({}).__proto__.__defineSetter__("k", function (v) { console.log("set", v); }); exports.k = 1; console.log(2);
            """),
        prints('set 1', '2'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'read back through module.children of a required file': FileProgram(
        a_program("""
            exports.a = 1; console.log(require("module")._cache[require.resolve(__filename)].exports.a);
            """),
        prints('1'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'a prototype swapped onto exports gives a later store a setter': FileProgram(
        a_program("""
            exports.__proto__ = { set x(v) { console.log("side", v); } }; exports.x = 5; console.log("end");
            """),
        prints('side 5', 'end'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'an inherited setter installed on Object.prototype': FileProgram(
        a_program("""
            Object.defineProperty(Object.prototype, "x", { set: function (v) { console.log("set", v); }, configurable: true }); exports.x = 1; console.log("end");
            """),
        prints('set 1', 'end'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'an inherited getter-only accessor makes a strict store throw': FileProgram(
        a_program("""
            "use strict"; Object.defineProperty(Object.prototype, "x", { get: function () { return 1; }, configurable: true }); try { exports.x = 2; console.log("stored"); } catch (e) { console.log(e.constructor.name); }
            """),
        prints('TypeError'),
        prints('ReferenceError'),
        HostEnvironment.node,
    ),
    'a host getter-only accessor on the module object': FileProgram(
        a_program("""
            "use strict"; try { module.isPreloading = true; console.log("stored"); } catch (e) { console.log(e.constructor.name); }
            """),
        prints('TypeError'),
        prints('ReferenceError'),
        HostEnvironment.node,
    ),
    'module.require is what require calls': FileProgram(
        a_program("""
            module.require = function (p) { return "intercepted " + p; }; console.log(require("fs"));
            """),
        prints('intercepted fs'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'module.filename decides where a relative require looks': FileProgram(
        a_program("""
            module.filename = "/nonexistent/x.js"; try { require("./snippet.js"); console.log("found"); } catch (e) { console.log(e.code); }
            """),
        prints('MODULE_NOT_FOUND'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'a prototype swapped onto the module object': FileProgram(
        a_program("""
            module.__proto__ = {}; try { require("fs"); console.log("ok"); } catch (e) { console.log(e.constructor.name); }
            """),
        prints('TypeError'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'the wrapper reached through caller, a store into exports read': FileProgram(
        a_program("""
            function f() { return f.caller.arguments[2].exports.x; } exports.x = 5; console.log(f());
            """),
        prints('5'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'this in a top-level arrow': FileProgram(
        a_program("""
            exports.x = 1; console.log((() => this.x)());
            """),
        prints('1'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'arguments in a top-level arrow': FileProgram(
        a_program("""
            exports.x = 1; console.log((() => arguments[0].x)());
            """),
        prints('1'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'the main module read through require of argv': FileProgram(
        a_program("""
            exports.x = 1; console.log(require(process.argv[1]).x);
            """),
        prints('1'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'a frozen Object.prototype makes a strict store throw': FileProgram(
        a_program("""
            "use strict"; Object.freeze(Object.prototype); try { exports.toString = 1; console.log("stored"); } catch (e) { console.log(e.constructor.name); }
            """),
        prints('TypeError'),
        prints('ReferenceError'),
        HostEnvironment.node,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAStoreIntoTheModuleObjectsStillPrintsWhatItPrints(TestBase):

    def testnode_prints_what_each_row_pins(self):
        node_prints_what_each_row_pins(self, A_STORE_INTO_THE_MODULE_OBJECTS)

    def test_each_program_still_prints_what_it_prints(self):
        each_reading_still_prints(
            self,
            A_STORE_INTO_THE_MODULE_OBJECTS,
            (Reading.COMMONJS, Reading.MODULE, Reading.ES_MODULE),
        )


#: Programs that read what they store in `module.exports` back through Node's module registry,
#: each with what Node makes of it as a CommonJS file and as an ES module.
A_FILE_READING_ITS_OWN_EXPORTS_THROUGH_THE_REGISTRY = {
    'the file requires itself': FileProgram(
        a_program("""
            module.exports = { a: 1 }; console.log(require(__filename).a);
            """),
        prints('1'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'process.mainModule': FileProgram(
        a_program("""
            module.exports = { a: 1 }; console.log(process.mainModule.exports.a);
            """),
        prints('1'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'the module cache through the module module': FileProgram(
        a_program("""
            module.exports = { a: 1 }; console.log(require("module")._cache[__filename].exports.a);
            """),
        prints('1'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'require.main': FileProgram(
        a_program("""
            module.exports = { a: 1 }; console.log(require.main.exports.a);
            """),
        prints('1'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'require.cache': FileProgram(
        a_program("""
            module.exports = { a: 1 }; console.log(require.cache[__filename].exports.a);
            """),
        prints('1'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFileReadingItsOwnExportsThroughTheRegistry(TestBase):

    def testnode_prints_what_each_row_pins(self):
        node_prints_what_each_row_pins(self, A_FILE_READING_ITS_OWN_EXPORTS_THROUGH_THE_REGISTRY)

    @wontfix(
        'reading the exports through the module registry is loading the file, which the run assumes '
        'no code does unless -l says so; no obfuscated file reads its own exports this way'
    )
    def test_each_program_still_prints_what_it_prints(self):
        each_reading_still_prints(
            self,
            A_FILE_READING_ITS_OWN_EXPORTS_THROUGH_THE_REGISTRY,
            (Reading.COMMONJS,),
        )

    def test_each_program_stays_as_written_where_other_files_load_it(self):
        rows = A_FILE_READING_ITS_OWN_EXPORTS_THROUGH_THE_REGISTRY
        self.assertEqual(
            {label: _loaded_by_other_files(row.text) for label, row in rows.items()},
            {label: printed(row.text) for label, row in rows.items()},
        )


class TestTheStoreReplacingTheExportsGoesWhereNothingReadsIt(TestBase):

    REPLACED = a_program("""
        module.exports = {a: 1};
        console.log(2);
        """)

    def _commonjs(self, source: str) -> str:
        return deobfuscate_source(source, execution=ExecutionModel.commonjs, environment=HostEnvironment.node)

    def test_the_store_goes_from_a_commonjs_file(self):
        self.assertEqual(self._commonjs(self.REPLACED), 'console.log(2);')

    def test_a_function_whose_only_effect_is_the_store_goes_with_its_call(self):
        source = a_program("""
            function init(v) {
              module.exports = v;
            }
            init(1);
            console.log(2);
            """)
        self.assertEqual(self._commonjs(source), 'console.log(2);')

    def test_the_store_under_the_guard_of_a_universal_module_goes(self):
        source = a_program("""
            "undefined" != typeof module && null != module && (module.exports = {v: 1});
            console.log(2);
            """)
        self.assertEqual(self._commonjs(source), 'console.log(2);')

    def test_the_store_stays_where_other_files_load_the_input(self):
        self.assertEqual(_loaded_by_other_files(self.REPLACED), printed(self.REPLACED))

    def test_the_store_stays_in_a_file_that_may_be_an_es_module(self):
        self.assertEqual(
            deobfuscate_source(self.REPLACED, execution=ExecutionModel.module, environment=HostEnvironment.node),
            printed(self.REPLACED),
        )

    def test_the_store_stays_in_a_classic_script_where_module_is_a_global(self):
        self.assertEqual(
            deobfuscate_source(self.REPLACED, execution=ExecutionModel.script, environment=HostEnvironment.node),
            printed(self.REPLACED),
        )

    def test_the_store_stays_where_the_file_reads_module_back(self):
        source = a_program("""
            module.exports = {a: 1};
            console.log(module.exports.a);
            """)
        self.assertEqual(self._commonjs(source), printed(source))

    def test_a_store_into_the_exports_object_stays(self):
        source = a_program("""
            exports.a = 1;
            console.log(2);
            """)
        self.assertEqual(self._commonjs(source), printed(source))
