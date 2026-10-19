"""
Programs whose meaning depends on what the file is: a classic script, a CommonJS file, or an ES
module. A CommonJS file is the body of a function the host calls, sloppy code where it says
nothing; an ES module is strict code throughout; in both a top-level declaration is scoped to the
file. Each row is run the way the reading it is asked under runs it, and deobfuscated for that
reading.
"""
from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import node_executable
from test.lib.scripts.js.deobfuscation.test_b91strings import SLICED, decoder, slicing
from test.lib.scripts.js.ledger import (
    FileProgram,
    Program,
    Reading,
    a_program,
    each_reading_still_prints,
    node_prints_what_each_row_pins,
    prints,
)

#: The three readings of a file Node runs as a module: `MODULE` and `ES_MODULE` share the text the
#: deobfuscation writes for a module of either kind and run it as a CommonJS file and as an ES
#: module, and `COMMONJS` runs the text written for a CommonJS file.
EVERY_MODULE_READING = (Reading.COMMONJS, Reading.MODULE, Reading.ES_MODULE)

#: Programs assigning a name nothing declares and reading the global back, each with what Node makes
#: of it as a CommonJS file and as an ES module.
A_BARE_WRITE = {
    'a bare write read back through globalThis': FileProgram(
        a_program("""
            leak = 5;
            console.log(globalThis.leak);
            """),
        prints('5'),
        ('', 'ReferenceError'),
    ),
    'a bare write in a strict file': FileProgram(
        a_program("""
            'use strict';
            try { leak = 5; } catch (e) { console.log(e.name); }
            console.log(typeof globalThis.leak);
            """),
        prints('ReferenceError', 'undefined'),
        prints('ReferenceError', 'undefined'),
    ),
}

#: Programs reading the global object through a `this`, each with what Node makes of it as a
#: CommonJS file and as an ES module.
A_THIS_THAT_MAY_BE_THE_GLOBAL_OBJECT = {
    'a top-level this written through': FileProgram(
        a_program("""
            this.g = 1;
            console.log(typeof globalThis.g);
            """),
        prints('undefined'),
        ('', 'TypeError'),
    ),
    'a global read through the this of a function called bare': FileProgram(
        a_program("""
            globalThis.g = 1;
            function f() { return this.g; }
            console.log(f());
            """),
        prints('1'),
        ('', 'TypeError'),
    ),
    'a global written through the this of a function called bare': FileProgram(
        a_program("""
            globalThis.g = 1;
            function f() { this.g = 5; }
            f();
            console.log(globalThis.g);
            """),
        prints('5'),
        ('', 'TypeError'),
    ),
    'a function returning this': FileProgram(
        a_program("""
            function g() { var p = typeof window; return this; }
            console.log(typeof g());
            """),
        prints('object'),
        prints('undefined'),
    ),
    'a function falling back on this': FileProgram(
        a_program("""
            function g() { try { return window; } catch (e) { return this; } }
            console.log(typeof g());
            """),
        prints('object'),
        prints('undefined'),
    ),
}

#: A classic script reading the global object through a top-level `this`, mapped to what a host
#: prints for it.
A_TOP_LEVEL_THIS_IN_A_SCRIPT = {
    'a top-level this written through': Program(
        a_program("""
            this.g = 1;
            console.log(typeof globalThis.g);
            """),
        prints('number'),
        Reading.SCRIPT,
    ),
}

#: Programs holding a function declared in a block, whose `var` half sloppy code makes and strict
#: code does not, each with what Node makes of it as a CommonJS file and as an ES module.
A_FUNCTION_DECLARED_IN_A_BLOCK = {
    'a dropped branch holding a block function': FileProgram(
        a_program("""
            globalThis.f = 'global';
            if (false) { function f() {} }
            console.log(f);
            """),
        prints('undefined'),
        prints('global'),
    ),
    'a generator dispatcher holding a block function': FileProgram(
        a_program("""
            function outer() {
              function* gen(a, b, scope = {}, args) {
                while (a + b !== 100) {
                  switch (a + b) {
                    case 10:
                      scope.peek = function () { { function a() {} } return a; };
                      a = 40, b = 0;
                      break;
                    case 40:
                      return done = true, scope.peek();
                      break;
                  }
                }
              }
              var done;
              var result = gen(5, 5)["next"]()["value"];
              if (done) { return result; }
            }
            console.log(String(outer()).slice(0, 12));
            """),
        prints('function a()'),
        prints('40'),
    ),
}

#: Programs whose direct `eval` in a parameter default declares a name the function reads, each with
#: what Node makes of it as a CommonJS file and as an ES module, where the `eval` is strict and
#: declares nothing outside itself.
A_DIRECT_EVAL_IN_A_DEFAULT_DECLARING_A_NAME = {
    'a var the eval declares, read by the body': FileProgram(
        a_program("""
            var v = 1;
            function f(x = eval('var v = 2')) { return v; }
            console.log(f());
            """),
        prints('2'),
        prints('1'),
    ),
    'a var the eval declares, read by a later default': FileProgram(
        a_program("""
            var v = 1;
            function f(a = eval('var v = 2'), b = v) { return b; }
            console.log(f());
            """),
        prints('2'),
        prints('1'),
    ),
}

#: Programs running a direct `eval` in the body of a function that declares a `var` named like a
#: top-level variable the function reads after it, each with what Node makes of it as a CommonJS
#: file and as an ES module.
A_DIRECT_EVAL_IN_A_BODY_DECLARING_A_NAME = {
    'a var the eval declares, read by the body': FileProgram(
        a_program("""
            var v = 1;
            function f(c) { eval(c); return v; }
            console.log(f("var v = 2"));
            """),
        prints('2'),
        prints('1'),
    ),
    'a var the eval declares, read by a function the body declares': FileProgram(
        a_program("""
            var v = 1;
            function f(c) { eval(c); function g() { return v; } return g(); }
            console.log(f("var v = 2"));
            """),
        prints('2'),
        prints('1'),
    ),
    'a var an eval below and declares, read by the body': FileProgram(
        a_program("""
            var x = 1;
            function f(c) { c && eval("var x = 2"); return x; }
            console.log(f(false), f(true));
            """),
        prints('1 2'),
        prints('1 1'),
    ),
    'a var an eval in an arm of a conditional declares, read by the body': FileProgram(
        a_program("""
            var x = 1;
            function f(c) { c ? eval("var x = 2") : 0; return x; }
            console.log(f(false), f(true));
            """),
        prints('1 2'),
        prints('1 1'),
    ),
}

#: Programs whose direct `eval` of a string no fold can read assigns a top-level variable that a
#: function reads, called after the `eval`, each with what Node makes of it as a CommonJS file and
#: as an ES module.
A_VARIABLE_AN_UNREADABLE_EVAL_ASSIGNS_READ_BY_A_FUNCTION = {
    'the eval at the top of the file': FileProgram(
        a_program("""
            var s = "abc";
            function f(n) { return s.slice(n); }
            eval(Date.now() > 0 ? "s = 'xyz'" : "");
            console.log(f(Math.random() > 2 ? 0 : 1));
            """),
        prints('yz'),
        prints('yz'),
    ),
    'the eval in another function': FileProgram(
        a_program("""
            var s = "abc";
            function f(n) { return s.slice(n); }
            function g() { eval(Date.now() > 0 ? "s = 'xyz'" : ""); }
            g();
            console.log(f(Math.random() > 2 ? 0 : 1));
            """),
        prints('yz'),
        prints('yz'),
    ),
    'the long string of a slicing accessor': FileProgram(
        SLICED
        + decoder('S_decode') + '\n'
        + slicing('S', 'S_decode') + '\n'
        + 'eval(Date.now() > 0 ? "strs = " + JSON.stringify("XXlrCD^") : "");\n'
        + 'console.log(S(2, 5));\n',
        prints('Fizz'),
        prints('Fizz'),
    ),
}

#: A program whose namespace object loses a key to code only an `eval` can read, with what Node
#: makes of it as a CommonJS file and as an ES module.
A_NAMESPACE_AN_UNREADABLE_EVAL_CHANGES = {
    'a key the eval deletes': FileProgram(
        a_program("""
            var X = {};
            X.k = 1;
            eval(process.argv[2] || 'delete X.k');
            console.log('k' in X);
            """),
        prints('false'),
        prints('false'),
    ),
}

#: Every program above whose top-level variable a direct `eval` of the file reaches.
A_TOP_LEVEL_VARIABLE_A_DIRECT_EVAL_REACHES = {
    **A_DIRECT_EVAL_IN_A_DEFAULT_DECLARING_A_NAME,
    **A_DIRECT_EVAL_IN_A_BODY_DECLARING_A_NAME,
    **A_VARIABLE_AN_UNREADABLE_EVAL_ASSIGNS_READ_BY_A_FUNCTION,
    **A_NAMESPACE_AN_UNREADABLE_EVAL_CHANGES,
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestABareWriteInSloppyCodeOfACommonJsFileCreatesTheGlobal(TestBase):
    """
    A CommonJS file is sloppy code where it says nothing, so assigning a name nothing declares
    creates a global there, and a read of the global afterwards is a read of the name. Where the
    file may be an ES module the assignment throws instead, and where the file says it is strict it
    throws either way.
    """

    def test_node_prints_what_each_row_pins(self):
        node_prints_what_each_row_pins(self, A_BARE_WRITE)

    def test_each_program_still_prints_what_it_prints(self):
        each_reading_still_prints(self, A_BARE_WRITE, EVERY_MODULE_READING)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAThisIsTheGlobalObjectOnlyWhereTheCodeIsSloppy(TestBase):
    """
    A top-level `this` is the global object in a classic script only: a CommonJS file runs with its
    exports there, and an ES module with `undefined`. A function called bare gets the global object
    for its `this` where its code is sloppy, which a CommonJS file's is where it says nothing and an
    ES module's never is.
    """

    def test_node_prints_what_each_row_pins(self):
        node_prints_what_each_row_pins(self, A_THIS_THAT_MAY_BE_THE_GLOBAL_OBJECT)

    def test_each_program_still_prints_what_it_prints(self):
        each_reading_still_prints(self, A_THIS_THAT_MAY_BE_THE_GLOBAL_OBJECT, EVERY_MODULE_READING)

    def test_a_host_prints_what_each_script_pins(self):
        for label, row in A_TOP_LEVEL_THIS_IN_A_SCRIPT.items():
            with self.subTest(label):
                self.assertEqual(row.behaves(), row.prints)

    def test_each_script_still_prints_what_it_prints(self):
        for label, row in A_TOP_LEVEL_THIS_IN_A_SCRIPT.items():
            with self.subTest(label):
                self.assertEqual(row.read(), row.required())


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFunctionDeclaredInABlockKeepsItsVarHalfOnlyInSloppyCode(TestBase):
    """
    Sloppy code gives a function declared in a block a `var` of its name in the function around the
    block, and strict code does not. A file that may be an ES module is read both ways, so neither
    a dropped branch nor a recovered dispatcher may settle whether that `var` exists where anything
    reads it.
    """

    def test_node_prints_what_each_row_pins(self):
        node_prints_what_each_row_pins(self, A_FUNCTION_DECLARED_IN_A_BLOCK)

    def test_each_program_still_prints_what_it_prints(self):
        each_reading_still_prints(self, A_FUNCTION_DECLARED_IN_A_BLOCK, EVERY_MODULE_READING)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestADirectEvalReachesTheTopLevelVariablesOfAModule(TestBase):
    """
    In a module of either kind a top-level variable is scoped to the file, and a direct `eval`
    anywhere in the file can name it: one in sloppy code declares a `var` of the same name in the
    function it runs in, and any can assign it. No value of such a variable is written into the
    code that reads it.
    """

    def test_node_prints_what_each_row_pins(self):
        node_prints_what_each_row_pins(self, A_TOP_LEVEL_VARIABLE_A_DIRECT_EVAL_REACHES)

    def test_each_program_still_prints_what_it_prints(self):
        each_reading_still_prints(
            self, A_TOP_LEVEL_VARIABLE_A_DIRECT_EVAL_REACHES, EVERY_MODULE_READING)
