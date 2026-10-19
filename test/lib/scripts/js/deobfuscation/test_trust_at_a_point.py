"""
A fold that trusts a built-in asks at its own point whether the program changed it before: a
`typeof` of a name the host lacks folds only where no code before it may create the name, and a
method call on a literal only where no code before it may replace the method. Code that runs after
the point does not hold the fold back.
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
    prints,
    wontfix,
)

from refinery.lib.scripts.js.analysis.environment import HostEnvironment
from refinery.lib.scripts.js.options import ExecutionModel


#: Programs that ask `typeof` of a name Node lacks where code before or after the question may
#: create the name, each with what Node makes of it as a CommonJS file and as an ES module.
A_TYPEOF_OF_A_NAME_THE_PROGRAM_MAY_CREATE = {
    'typeof of a name created later at a runtime key': FileProgram(
        a_program("""
            console.log(typeof define); globalThis[process.argv.length > 99 ? "x" : "define"] = 1; console.log(typeof define);
            """),
        prints('undefined', 'number'),
        prints('undefined', 'number'),
        HostEnvironment.node,
    ),
    'typeof in a function called before and after': FileProgram(
        a_program("""
            function f() { return typeof angular; } console.log(f()); globalThis[process.argv.length > 99 ? "x" : "angular"] = 1; console.log(f());
            """),
        prints('undefined', 'number'),
        prints('undefined', 'number'),
        HostEnvironment.node,
    ),
    'typeof in a loop around the write': FileProgram(
        a_program("""
            for (var k = 0; k < 2; k++) { console.log(typeof define); globalThis[process.argv.length > 99 ? "x" : "define"] = 2; }
            """),
        prints('undefined', 'number'),
        prints('undefined', 'number'),
        HostEnvironment.node,
    ),
    'the name created through globalThis first': FileProgram(
        a_program("""
            globalThis.define = 3; console.log(typeof define);
            """),
        prints('number'),
        prints('number'),
        HostEnvironment.node,
    ),
    'the name created through global': FileProgram(
        a_program("""
            global.define = 1; console.log(typeof define);globalThis[process.argv.length > 99 ? "a" : "b"] = 2;
            """),
        prints('number'),
        prints('number'),
        HostEnvironment.node,
    ),
    'Object.defineProperty on globalThis': FileProgram(
        a_program("""
            Object.defineProperty(globalThis, "define", { value: 1 }); console.log(typeof define);globalThis[process.argv.length > 99 ? "a" : "b"] = 2;
            """),
        prints('number'),
        prints('number'),
        HostEnvironment.node,
    ),
    'Object.assign onto globalThis': FileProgram(
        a_program("""
            Object.assign(globalThis, { angular: {} }); console.log(typeof angular);globalThis[process.argv.length > 99 ? "a" : "b"] = 2;
            """),
        prints('object'),
        prints('object'),
        HostEnvironment.node,
    ),
    'a global object found by Function': FileProgram(
        a_program("""
            var g = Function("return this")(); g.define = 1; console.log(typeof define);globalThis[process.argv.length > 99 ? "a" : "b"] = 2;
            """),
        prints('number'),
        prints('number'),
        HostEnvironment.node,
    ),
    'with, the name a property of the object': FileProgram(
        a_program("""
            with ({ define: 1 }) { console.log(typeof define); }globalThis[process.argv.length > 99 ? "a" : "b"] = 2;
            """),
        prints('number'),
        ('', 'SyntaxError'),
        HostEnvironment.node,
    ),
    'with, the name a property of the object, without a surface': FileProgram(
        a_program("""
            with ({ define: 1 }) { console.log(typeof define); }
            """),
        prints('number'),
        ('', 'SyntaxError'),
        HostEnvironment.node,
    ),
    'a direct eval creates the name': FileProgram(
        a_program("""
            eval(process.argv.length > 99 ? "" : "var define = 1"); console.log(typeof define);
            """),
        prints('number'),
        prints('undefined'),
        HostEnvironment.node,
    ),
    'an implicit global in a function called first': FileProgram(
        a_program("""
            function mk() { define = 1; } mk(); console.log(typeof define);globalThis[process.argv.length > 99 ? "a" : "b"] = 2;
            """),
        prints('number'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'the prototype of globalThis replaced': FileProgram(
        a_program("""
            Object.setPrototypeOf(globalThis, { define: 1 }); console.log(typeof define);globalThis[process.argv.length > 99 ? "a" : "b"] = 2;
            """),
        prints('number'),
        prints('number'),
        HostEnvironment.node,
    ),
    'Reflect.set on globalThis': FileProgram(
        a_program("""
            Reflect.set(globalThis, "define", 1); console.log(typeof define);globalThis[process.argv.length > 99 ? "a" : "b"] = 2;
            """),
        prints('number'),
        prints('number'),
        HostEnvironment.node,
    ),
    'Buffer deleted before, a runtime-keyed global write after': FileProgram(
        a_program("""
            delete globalThis.Buffer; console.log(typeof Buffer);globalThis[process.argv.length > 99 ? "x" : "y"] = 1;
            """),
        prints('undefined'),
        prints('undefined'),
        HostEnvironment.node,
    ),
    'Buffer deleted by Reflect before': FileProgram(
        a_program("""
            Reflect.deleteProperty(globalThis, "Buffer"); console.log(typeof Buffer);globalThis[process.argv.length > 99 ? "x" : "y"] = 1;
            """),
        prints('undefined'),
        prints('undefined'),
        HostEnvironment.node,
    ),
    'Buffer redefined before': FileProgram(
        a_program("""
            Object.defineProperty(globalThis, "Buffer", { value: 5 }); console.log(typeof Buffer);globalThis[process.argv.length > 99 ? "x" : "y"] = 1;
            """),
        prints('number'),
        prints('number'),
        HostEnvironment.node,
    ),
    'Buffer deleted through global before': FileProgram(
        a_program("""
            delete global.Buffer; console.log(typeof Buffer);globalThis[process.argv.length > 99 ? "x" : "y"] = 1;
            """),
        prints('undefined'),
        prints('undefined'),
        HostEnvironment.node,
    ),
    'Buffer shadowed by with': FileProgram(
        a_program("""
            with ({ Buffer: 5 }) { console.log(typeof Buffer); }globalThis[process.argv.length > 99 ? "x" : "y"] = 1;
            """),
        prints('number'),
        ('', 'SyntaxError'),
        HostEnvironment.node,
    ),
    'eval replaced through a found global object before': FileProgram(
        a_program("""
            var g = Function("return this")(); g.eval = 5; console.log(typeof eval);globalThis[process.argv.length > 99 ? "x" : "y"] = 1;
            """),
        prints('number'),
        prints('number'),
        HostEnvironment.node,
    ),
    'setTimeout deleted through Object.getPrototypeOf': FileProgram(
        a_program("""
            delete Object.getPrototypeOf(Object.getPrototypeOf(globalThis)).constructor; delete globalThis.setTimeout; console.log(typeof setTimeout);globalThis[process.argv.length > 99 ? "x" : "y"] = 1;
            """),
        prints('undefined'),
        prints('undefined'),
        HostEnvironment.node,
    ),
    'typeof define in an array joined, after the program set define': FileProgram(
        a_program("""
            globalThis.define = 3; console.log([typeof define].join(""));
            """),
        prints('number'),
        prints('number'),
        HostEnvironment.node,
    ),
    'typeof angular in an array joined, after the program set angular': FileProgram(
        a_program("""
            globalThis.angular = {}; console.log([typeof angular].join(""));
            """),
        prints('object'),
        prints('object'),
        HostEnvironment.node,
    ),
    'typeof define in a decoder function, after the program set define': FileProgram(
        a_program("""
            globalThis.define = function () {}; function f() { return typeof define + "!"; } console.log(f());
            """),
        prints('function!'),
        prints('function!'),
        HostEnvironment.node,
    ),
    'typeof window in an array joined, after the program set window': FileProgram(
        a_program("""
            globalThis.window = 3; console.log([typeof window].join(""));
            """),
        prints('number'),
        prints('number'),
        HostEnvironment.node,
    ),
    'a typeof joined into a string after a write at a runtime key': FileProgram(
        a_program("""
            globalThis[process.argv.length > 99 ? "x" : "window"] = 1; console.log([typeof window].join(""));
            """),
        prints('number'),
        prints('number'),
        HostEnvironment.node,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestATypeofOfANameTheProgramMayCreateStillPrintsWhatItPrints(TestBase):

    def testnode_prints_what_each_row_pins(self):
        node_prints_what_each_row_pins(self, A_TYPEOF_OF_A_NAME_THE_PROGRAM_MAY_CREATE)

    def test_each_program_still_prints_what_it_prints(self):
        each_reading_still_prints(self, A_TYPEOF_OF_A_NAME_THE_PROGRAM_MAY_CREATE, (Reading.COMMONJS,))


#: Programs that create a name Node lacks on `Object.prototype` or on the prototype of the global
#: object before a `typeof` of it, each with what Node makes of it as a CommonJS file and as an ES
#: module.
A_NAME_CREATED_ON_A_PROTOTYPE_OF_THE_GLOBAL_OBJECT = {
    'the name created on Object.prototype': FileProgram(
        a_program("""
            Object.prototype.define = function () {}; console.log(typeof define);globalThis[process.argv.length > 99 ? "a" : "b"] = 2;
            """),
        prints('function'),
        prints('function'),
        HostEnvironment.node,
    ),
    'the name created on Object.prototype, without a surface': FileProgram(
        a_program("""
            Object.prototype.define = function () {}; console.log(typeof define);
            """),
        prints('function'),
        prints('function'),
        HostEnvironment.node,
    ),
    '__proto__ of globalThis written': FileProgram(
        a_program("""
            globalThis.__proto__.define = 1; console.log(typeof define);globalThis[process.argv.length > 99 ? "a" : "b"] = 2;
            """),
        prints('number'),
        prints('number'),
        HostEnvironment.node,
    ),
    'window created on Object.prototype': FileProgram(
        a_program("""
            Object.prototype.window = 1; console.log(typeof window);
            """),
        prints('number'),
        prints('number'),
        HostEnvironment.node,
    ),
    'window on the prototype of globalThis': FileProgram(
        a_program("""
            globalThis.__proto__.window = 1; console.log(typeof window);
            """),
        prints('number'),
        prints('number'),
        HostEnvironment.node,
    ),
    'window on Object.prototype before, a runtime-keyed global write after': FileProgram(
        a_program("""
            Object.prototype.window = 1; console.log(typeof window);globalThis[process.argv.length > 99 ? "x" : "y"] = 1;
            """),
        prints('number'),
        prints('number'),
        HostEnvironment.node,
    ),
    'window on the global prototype before, a runtime-keyed global write after': FileProgram(
        a_program("""
            globalThis.__proto__.window = 1; console.log(typeof window);globalThis[process.argv.length > 99 ? "x" : "y"] = 1;
            """),
        prints('number'),
        prints('number'),
        HostEnvironment.node,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestANameCreatedOnAPrototypeOfTheGlobalObject(TestBase):

    def testnode_prints_what_each_row_pins(self):
        node_prints_what_each_row_pins(self, A_NAME_CREATED_ON_A_PROTOTYPE_OF_THE_GLOBAL_OBJECT)

    @wontfix(
        'no obfuscated file creates a global name on Object.prototype or on the prototype of the '
        'global object, and the typeof fold has never seen such a write'
    )
    def test_each_program_still_prints_what_it_prints(self):
        each_reading_still_prints(self, A_NAME_CREATED_ON_A_PROTOTYPE_OF_THE_GLOBAL_OBJECT, (Reading.COMMONJS,))


#: Programs that call a method on a literal where code before or after the call may replace the
#: method, each with what Node makes of it as a CommonJS file and as an ES module.
A_METHOD_CALL_ON_A_LITERAL_THE_PROGRAM_MAY_REPLACE = {
    'a split before and after a runtime-keyed replacement': FileProgram(
        a_program("""
            console.log("a|b".split("|").length); String.prototype[process.argv.length > 99 ? "x" : "split"] = function () { return ["z"]; }; console.log("a|b".split("|").length);
            """),
        prints('2', '1'),
        prints('2', '1'),
        HostEnvironment.node,
    ),
    'a split in a function called before and after': FileProgram(
        a_program("""
            function f() { return "a|b".split("|").length; } console.log(f()); String.prototype[process.argv.length > 99 ? "x" : "split"] = function () { return []; }; console.log(f());
            """),
        prints('2', '0'),
        prints('2', '0'),
        HostEnvironment.node,
    ),
    'Symbol.split on String.prototype': FileProgram(
        a_program("""
            String.prototype[Symbol.split] = function () { return ["pwn"]; }; console.log("a|b".split("|"));globalThis[process.argv.length > 99 ? "a" : "b"] = 2;
            """),
        prints('[ \'pwn\' ]'),
        prints('[ \'pwn\' ]'),
        HostEnvironment.node,
    ),
    'split defined by defineProperty': FileProgram(
        a_program("""
            Object.defineProperty(String.prototype, "split", { value: function () { return ["pwn"]; } }); console.log("a|b".split("|"));globalThis[process.argv.length > 99 ? "a" : "b"] = 2;
            """),
        prints('[ \'pwn\' ]'),
        prints('[ \'pwn\' ]'),
        HostEnvironment.node,
    ),
    'split deleted, Object.prototype one installed': FileProgram(
        a_program("""
            delete String.prototype.split; Object.prototype.split = function () { return ["pwn"]; }; console.log("a|b".split("|"));globalThis[process.argv.length > 99 ? "a" : "b"] = 2;
            """),
        prints('[ \'pwn\' ]'),
        prints('[ \'pwn\' ]'),
        HostEnvironment.node,
    ),
    'a computed write through an alias': FileProgram(
        a_program("""
            var p = String.prototype, k = ["sp", "lit"].join(""); p[k] = function () { return ["pwn"]; }; console.log("a|b".split("|"));globalThis[process.argv.length > 99 ? "a" : "b"] = 2;
            """),
        prints('[ \'pwn\' ]'),
        prints('[ \'pwn\' ]'),
        HostEnvironment.node,
    ),
    'Symbol.split on Object.prototype before, a runtime-keyed String write after': FileProgram(
        a_program("""
            Object.prototype[Symbol.split] = function () { return ["pwn"]; }; console.log("a|b".split("|"));String.prototype[process.argv.length > 99 ? "x" : "split"] = function () { return []; };
            """),
        prints('[ \'pwn\' ]'),
        prints('[ \'pwn\' ]'),
        HostEnvironment.node,
    ),
    'split through an alias before, a runtime-keyed String write after': FileProgram(
        a_program("""
            var p = Object.getPrototypeOf(""); p.split = function () { return ["pwn"]; }; console.log("a|b".split("|"));String.prototype[process.argv.length > 99 ? "x" : "split"] = function () { return []; };
            """),
        prints('[ \'pwn\' ]'),
        prints('[ \'pwn\' ]'),
        HostEnvironment.node,
    ),
    'split through __proto__ before, a runtime-keyed String write after': FileProgram(
        a_program("""
            "".__proto__.split = function () { return ["pwn"]; }; console.log("a|b".split("|"));String.prototype[process.argv.length > 99 ? "x" : "split"] = function () { return []; };
            """),
        prints('[ \'pwn\' ]'),
        prints('[ \'pwn\' ]'),
        HostEnvironment.node,
    ),
    'Symbol.replace before, a runtime-keyed String write after': FileProgram(
        a_program("""
            Object.prototype[Symbol.replace] = function () { return "pwn"; }; console.log("abc".replace("b", "x"));String.prototype[process.argv.length > 99 ? "x" : "split"] = function () { return []; };
            """),
        prints('pwn'),
        prints('pwn'),
        HostEnvironment.node,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAMethodCallOnALiteralStillPrintsWhatItPrints(TestBase):

    def testnode_prints_what_each_row_pins(self):
        node_prints_what_each_row_pins(self, A_METHOD_CALL_ON_A_LITERAL_THE_PROGRAM_MAY_REPLACE)

    def test_each_program_still_prints_what_it_prints(self):
        each_reading_still_prints(self, A_METHOD_CALL_ON_A_LITERAL_THE_PROGRAM_MAY_REPLACE, (Reading.COMMONJS,))


#: Programs that replace a method of strings before calling it on a literal through a symbol on
#: `Object.prototype` or through the prototype of a literal, each with what Node makes of it as a
#: CommonJS file and as an ES module.
A_METHOD_REPLACED_THROUGH_A_SYMBOL_OR_THE_PROTOTYPE_OF_A_LITERAL = {
    'Symbol.split on Object.prototype': FileProgram(
        a_program("""
            Object.prototype[Symbol.split] = function () { return ["pwn"]; }; console.log("a|b".split("|"));globalThis[process.argv.length > 99 ? "a" : "b"] = 2;
            """),
        prints('[ \'pwn\' ]'),
        prints('[ \'pwn\' ]'),
        HostEnvironment.node,
    ),
    'Symbol.split on Object.prototype, without a surface': FileProgram(
        a_program("""
            Object.prototype[Symbol.split] = function () { return ["pwn"]; }; console.log("a|b".split("|"));
            """),
        prints('[ \'pwn\' ]'),
        prints('[ \'pwn\' ]'),
        HostEnvironment.node,
    ),
    'split written through an alias of String.prototype': FileProgram(
        a_program("""
            var p = Object.getPrototypeOf(""); p.split = function () { return ["pwn"]; }; console.log("a|b".split("|"));globalThis[process.argv.length > 99 ? "a" : "b"] = 2;
            """),
        prints('[ \'pwn\' ]'),
        prints('[ \'pwn\' ]'),
        HostEnvironment.node,
    ),
    'Symbol.replace on Object.prototype': FileProgram(
        a_program("""
            Object.prototype[Symbol.replace] = function () { return "pwn"; }; console.log("abc".replace("b", "x"));globalThis[process.argv.length > 99 ? "a" : "b"] = 2;
            """),
        prints('pwn'),
        prints('pwn'),
        HostEnvironment.node,
    ),
    'a write through __proto__ of a literal': FileProgram(
        a_program("""
            "".__proto__.split = function () { return ["pwn"]; }; console.log("a|b".split("|"));globalThis[process.argv.length > 99 ? "a" : "b"] = 2;
            """),
        prints('[ \'pwn\' ]'),
        prints('[ \'pwn\' ]'),
        HostEnvironment.node,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAMethodReplacedThroughASymbolOrThePrototypeOfALiteral(TestBase):

    def testnode_prints_what_each_row_pins(self):
        node_prints_what_each_row_pins(self, A_METHOD_REPLACED_THROUGH_A_SYMBOL_OR_THE_PROTOTYPE_OF_A_LITERAL)

    @wontfix(
        'no obfuscated file sets Symbol.split or Symbol.replace on Object.prototype or writes a '
        'string method through the prototype of a literal, and the fold of a method call has never '
        'seen such a write'
    )
    def test_each_program_still_prints_what_it_prints(self):
        each_reading_still_prints(
            self,
            A_METHOD_REPLACED_THROUGH_A_SYMBOL_OR_THE_PROTOTYPE_OF_A_LITERAL,
            (Reading.COMMONJS,),
        )


class TestAFoldIsAskedAtItsPoint(TestBase):

    def test_a_typeof_before_a_write_at_a_runtime_key_folds_and_one_after_it_stays(self):
        source = a_program("""
            console.log(typeof define);
            globalThis[process.argv.length > 99 ? "x" : "define"] = 1;
            console.log(typeof define);
            """)
        self.assertEqual(
            deobfuscate_source(source, execution=ExecutionModel.commonjs, environment=HostEnvironment.node),
            inspect.cleandoc("""
                console.log('undefined');
                globalThis[process.argv.length > 99 ? "x" : "define"] = 1;
                console.log(typeof define);
                """),
        )
