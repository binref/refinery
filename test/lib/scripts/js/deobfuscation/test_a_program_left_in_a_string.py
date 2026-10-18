"""
Programs that leave part of themselves in a string, which a `Function` construction or an `eval`
runs, read the way Node reads a file it runs as a module.

A CommonJS file is sloppy code unless it says otherwise, so where `refinery.js` is told the file is
one, a payload that runs differently as strict code is unpacked into it. Where the file may be an
ES module as well, such a payload stays in its string, because unpacked it would run as strict
code. Either way a payload reading a name the CommonJS wrapper binds — `require`, `module`,
`exports`, `__filename`, `__dirname` — stays in its string: the string runs as global code, which
does not see these names, and the same text unpacked into the file would read the wrapper's. So
does a payload declaring one where it would land at the top of the file, which is the body of the
function the wrapper is, and a payload holding a direct `eval`, which reads the scope it runs in.
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
from test.lib.scripts.js.ledger import (
    NL,
    Behavior,
    Program,
    Reading,
    a_program,
    printed,
    prints,
)

from refinery.lib.scripts.js.options import ExecutionModel
from refinery.units.scripting.js import js


class Payload(NamedTuple):
    """
    A program running part of itself from a string, with what Node makes of it run as a CommonJS
    file and run as an ES module.
    """
    text: str
    as_commonjs: Behavior
    as_an_es_module: Behavior

    def read_as(self, reading: Reading) -> Program:
        if reading is Reading.ES_MODULE:
            return Program(self.text, self.as_an_es_module, reading)
        return Program(self.text, self.as_commonjs, reading)


def _runs_a_string(source: str) -> bool:
    return any(call in source for call in ('Function(', 'eval(', 'eval)('))


def _each_reading_still_prints(
    test: unittest.TestCase,
    rows: dict[str, Payload],
    readings: tuple[Reading, ...],
):
    for label, row in rows.items():
        for reading in readings:
            program = row.read_as(reading)
            with test.subTest(label=label, reading=reading.name):
                test.assertEqual(program.read(), program.required())


def _node_prints_what_each_row_pins(test: unittest.TestCase, rows: dict[str, Payload]):
    for label, row in rows.items():
        for reading in (Reading.COMMONJS, Reading.ES_MODULE):
            program = row.read_as(reading)
            with test.subTest(label=label, reading=reading.name):
                test.assertEqual(program.behaves(), program.prints)


#: Programs whose payload runs differently as strict code, each with what Node makes of it as a
#: CommonJS file and as an ES module.
A_PAYLOAD_ONLY_SLOPPY_CODE_RUNS_AS_WRITTEN = {
    'a nested function reads this': Payload(
        a_program("""
            Function("function f() { return typeof this; } console.log(f());")();
            """),
        prints('object'),
        prints('object'),
    ),
    'an implicit global write': Payload(
        a_program("""
            Function("leak = 5;")();
            console.log(globalThis.leak);
            """),
        prints('5'),
        prints('5'),
    ),
    'a write to a frozen object through the accessor object': Payload(
        a_program("""
            var o = Object.freeze({a: 1});
            Function("p", "p.o.a = 2; console.log(p.o.a);")({ get o() { return o; } });
            """),
        prints('1'),
        prints('1'),
    ),
    'a with statement': Payload(
        a_program("""
            Function("with ({a: 1}) console.log(a);")();
            """),
        prints('1'),
        prints('1'),
    ),
    'a block function read after its block': Payload(
        a_program("""
            Function("{ function g() { return 1; } } console.log(typeof g);")();
            """),
        prints('function'),
        prints('function'),
    ),
    'a mapped arguments object': Payload(
        a_program("""
            Function("function k(a) { a = 2; return arguments[0]; } console.log(k(1));")();
            """),
        prints('2'),
        prints('2'),
    ),
    'a read of arguments.callee': Payload(
        a_program("""
            Function("function k() { return typeof arguments.callee; } console.log(k());")();
            """),
        prints('function'),
        prints('function'),
    ),
    'a legacy octal literal': Payload(
        a_program("""
            Function("console.log(010);")();
            """),
        prints('8'),
        prints('8'),
    ),
    'a delete of an unqualified name': Payload(
        a_program("""
            Function("x9 = 1; console.log(delete x9);")();
            """),
        prints('true'),
        prints('true'),
    ),
    'a write to undefined': Payload(
        a_program("""
            Function("undefined = 5; console.log(typeof undefined);")();
            """),
        prints('undefined'),
        prints('undefined'),
    ),
    'a file reading this at its top level after the payload ran': Payload(
        a_program("""
            Function("leak19 = 1;")();
            console.log(this === module.exports, globalThis.leak19);
            """),
        prints('true 1'),
        ('', 'ReferenceError'),
    ),
    'await as a name': Payload(
        a_program("""
            Function("var await = 3; console.log(await);")();
            """),
        prints('3'),
        prints('3'),
    ),
    'an HTML-like comment': Payload(
        a_program(r"""
            Function("console.log(1); <!-- ignored\nconsole.log(2);")();
            """),
        prints('1', '2'),
        prints('1', '2'),
    ),
    'yield as a name': Payload(
        a_program("""
            Function("var yield = 4; console.log(yield);")();
            """),
        prints('4'),
        prints('4'),
    ),
    'a direct eval declaring a var at the top of the file': Payload(
        a_program("""
            eval("var q = 1;");
            console.log(q, typeof globalThis.q);
            """),
        prints('1 undefined'),
        ('', 'ReferenceError'),
    ),
    'a direct eval declaring a function at the top of the file': Payload(
        a_program("""
            eval("function h() { return 2; }");
            console.log(h(), typeof globalThis.h);
            """),
        prints('2 undefined'),
        ('', 'ReferenceError'),
    ),
    'a direct eval in a function declaring a var read after it': Payload(
        a_program("""
            function f() { eval("var z = 1;"); return z; }
            console.log(f(), typeof z);
            """),
        prints('1 undefined'),
        ('', 'ReferenceError'),
    ),
}

#: Packed programs whose payload runs alike as strict code, each with what Node makes of it as a
#: CommonJS file and as an ES module. A file known to be CommonJS holds each unpacked; whether a
#: file that may be an ES module does is left to the strict-mode check.
A_PACKED_PROGRAM_STRICT_CODE_RUNS_ALIKE = {
    'a packed program spreading a frozen object': Payload(
        a_program("""
            Function("Q", "const D = Object.freeze({a: 1, b: 2}); const o = {...D}; o.a = 3; console.log(JSON.stringify(o), D.a);")({});
            """),
        prints('{"a":3,"b":2} 1'),
        prints('{"a":3,"b":2} 1'),
    ),
    'a packed program with a class and an async tail': Payload(
        a_program("""
            Function("Q", "class E extends Error {} console.log(new E() instanceof E); return (async () => console.log('done'))();")({});
            """),
        prints('true', 'done'),
        prints('true', 'done'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAPayloadOnlySloppyCodeRunsAsWrittenIsUnpackedOnlyIntoACommonJsFile(TestBase):

    def test_node_prints_what_each_row_pins(self):
        _node_prints_what_each_row_pins(self, A_PAYLOAD_ONLY_SLOPPY_CODE_RUNS_AS_WRITTEN)

    def test_a_commonjs_file_holds_each_payload_unpacked(self):
        rows = A_PAYLOAD_ONLY_SLOPPY_CODE_RUNS_AS_WRITTEN
        unpacked = {
            label: deobfuscate_source(row.text, execution=ExecutionModel.commonjs)
            for label, row in rows.items()
        }
        self.assertEqual(
            {label: _runs_a_string(text) for label, text in unpacked.items()},
            {label: False for label in rows},
        )

    def test_a_commonjs_file_still_prints_what_each_program_prints(self):
        _each_reading_still_prints(
            self,
            A_PAYLOAD_ONLY_SLOPPY_CODE_RUNS_AS_WRITTEN,
            (Reading.COMMONJS,),
        )

    def test_a_file_that_may_be_an_es_module_keeps_each_payload_as_written(self):
        rows = A_PAYLOAD_ONLY_SLOPPY_CODE_RUNS_AS_WRITTEN
        self.assertEqual(
            {
                label: deobfuscate_source(row.text, execution=ExecutionModel.module)
                for label, row in rows.items()
            },
            {label: printed(row.text) for label, row in rows.items()},
        )

    def test_a_file_that_may_be_an_es_module_still_prints_what_each_program_prints(self):
        _each_reading_still_prints(
            self,
            A_PAYLOAD_ONLY_SLOPPY_CODE_RUNS_AS_WRITTEN,
            (Reading.MODULE, Reading.ES_MODULE),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAPackedProgramStrictCodeRunsAlikeIsUnpackedIntoACommonJsFile(TestBase):

    def test_node_prints_what_each_row_pins(self):
        _node_prints_what_each_row_pins(self, A_PACKED_PROGRAM_STRICT_CODE_RUNS_ALIKE)

    def test_a_commonjs_file_holds_each_payload_unpacked(self):
        rows = A_PACKED_PROGRAM_STRICT_CODE_RUNS_ALIKE
        unpacked = {
            label: deobfuscate_source(row.text, execution=ExecutionModel.commonjs)
            for label, row in rows.items()
        }
        self.assertEqual(
            {label: _runs_a_string(text) for label, text in unpacked.items()},
            {label: False for label in rows},
        )

    def test_each_program_still_prints_what_it_prints(self):
        _each_reading_still_prints(
            self,
            A_PACKED_PROGRAM_STRICT_CODE_RUNS_ALIKE,
            (Reading.COMMONJS, Reading.MODULE, Reading.ES_MODULE),
        )


#: Programs whose payload runs differently as strict code, called where the file's own text makes
#: the code strict, each with what Node makes of it as a CommonJS file.
A_PAYLOAD_AT_A_STRICT_SITE = {
    'a file with a use strict prologue': Program(
        a_program("""
            'use strict';
            Function("leak11 = 5;")();
            console.log(typeof leak11);
            """),
        prints('number'),
        Reading.COMMONJS,
    ),
    'a site in a strict function': Program(
        a_program("""
            function f() { 'use strict'; Function("leak13 = 7;")(); }
            f();
            console.log(globalThis.leak13);
            """),
        prints('7'),
        Reading.COMMONJS,
    ),
    'a site in a class body': Program(
        a_program("""
            class C { m() { Function("leak14 = 8;")(); } }
            new C().m();
            console.log(globalThis.leak14);
            """),
        prints('8'),
        Reading.COMMONJS,
    ),
}

#: A file spelling `export`, which Node runs as an ES module only, so its code is strict code
#: whatever `refinery.js` is told about it.
A_FILE_SPELLING_EXPORT = a_program("""
    export {};
    Function("leak12 = 6;")();
    console.log(globalThis.leak12);
    """)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAPayloadAtAStrictSiteStaysInItsStringInACommonJsFile(TestBase):

    def test_node_prints_what_each_row_pins(self):
        for label, row in A_PAYLOAD_AT_A_STRICT_SITE.items():
            with self.subTest(label):
                self.assertEqual(row.behaves(), row.prints)

    def test_each_payload_stays_as_written(self):
        rows = A_PAYLOAD_AT_A_STRICT_SITE
        self.assertEqual(
            {
                label: deobfuscate_source(row.text, execution=ExecutionModel.commonjs)
                for label, row in rows.items()
            },
            {label: printed(row.text) for label, row in rows.items()},
        )

    def test_each_program_still_prints_what_it_prints(self):
        for label, row in A_PAYLOAD_AT_A_STRICT_SITE.items():
            with self.subTest(label):
                self.assertEqual(row.read(), row.required())

    def test_a_file_spelling_export_keeps_its_payload_as_written(self):
        self.assertEqual(
            deobfuscate_source(A_FILE_SPELLING_EXPORT, execution=ExecutionModel.commonjs),
            printed(A_FILE_SPELLING_EXPORT),
        )

    def test_a_file_spelling_export_still_prints_what_it_prints_as_an_es_module(self):
        rewritten = deobfuscate_source(A_FILE_SPELLING_EXPORT, execution=ExecutionModel.commonjs)
        self.assertEqual(
            (behavior(A_FILE_SPELLING_EXPORT, module=True), behavior(rewritten, module=True)),
            (prints('6'), prints('6')),
        )


#: Programs whose payload reads a name the CommonJS wrapper binds, each with what Node makes of it
#: as a CommonJS file and as an ES module. The string runs as global code, where none of these names
#: is bound; an assignment the file makes to one writes the wrapper's parameter and binds none.
A_PAYLOAD_READING_A_WRAPPER_NAME = {
    'a Function body returning typeof require': Payload(
        a_program("""
            console.log(Function("return typeof require")());
            """),
        prints('undefined'),
        prints('undefined'),
    ),
    'a Function body printing typeof module': Payload(
        a_program("""
            Function("console.log(typeof module)")();
            """),
        prints('undefined'),
        prints('undefined'),
    ),
    'a packed body printing typeof exports': Payload(
        a_program("""
            Function("p", "console.log(typeof exports)")({});
            """),
        prints('undefined'),
        prints('undefined'),
    ),
    'an indirect eval of typeof __dirname': Payload(
        a_program("""
            console.log((0, eval)("typeof __dirname"));
            """),
        prints('undefined'),
        prints('undefined'),
    ),
    'an indirect eval of typeof __filename': Payload(
        a_program("""
            console.log((0, eval)("typeof __filename"));
            """),
        prints('undefined'),
        prints('undefined'),
    ),
    'a Function body inside a function returning typeof require': Payload(
        a_program("""
            function f() { return Function("return typeof require")(); }
            console.log(f());
            """),
        prints('undefined'),
        prints('undefined'),
    ),
    'a Function body declaring var exports the file reads after it': Payload(
        a_program("""
            Function("var exports = 3; console.log(exports)")();
            console.log(typeof exports);
            """),
        prints('3', 'object'),
        prints('3', 'undefined'),
    ),
    'a Function body testing for module as a UMD wrapper does': Payload(
        a_program("""
            Function("var api = {v: 1}; if (typeof module === 'object') module.exports = api; else globalThis.api = api;")();
            console.log(typeof globalThis.api);
            """),
        prints('object'),
        prints('object'),
    ),
    'a file declaring its own var require': Payload(
        a_program("""
            var require = 5;
            console.log(Function("return typeof require")(), require);
            """),
        prints('undefined 5'),
        prints('undefined 5'),
    ),
    'a Function body reading exports in a file assigning it': Payload(
        a_program("""
            exports = module.exports = {};
            console.log(Function("return typeof exports")());
            """),
        prints('undefined'),
        ('', 'ReferenceError'),
    ),
}

#: Programs whose payload declares a name the CommonJS wrapper binds inside a function of the file,
#: or reads one through an accessor the file defines, each with what Node makes of it as a CommonJS
#: file and as an ES module.
A_PAYLOAD_BINDING_A_WRAPPER_NAME_FOR_ITSELF = {
    'a Function body inside a function declaring let module': Payload(
        a_program("""
            function g() { Function("let module = 1; console.log(module)")(); }
            g();
            console.log(typeof module);
            """),
        prints('1', 'object'),
        prints('1', 'undefined'),
    ),
    'a packed body reading module through an accessor': Payload(
        a_program("""
            Function("p", "var m = p.m; console.log(typeof m.exports)")({ get m() { return module; } });
            """),
        prints('object'),
        ('', 'ReferenceError'),
    ),
}

#: Programs whose payload declares a name the CommonJS wrapper binds where it would land at the top
#: of the file, each with what Node makes of it as a CommonJS file and as an ES module. The top of a
#: CommonJS file is the body of the function the wrapper is: a `let`, `const` or `class` there
#: redeclares a parameter, which Node refuses to compile as CommonJS and runs as an ES module, and a
#: `var` there is the parameter itself, holding what the host passed.
A_PAYLOAD_DECLARING_A_WRAPPER_NAME_AT_THE_TOP_OF_THE_FILE = {
    'a Function body declaring let module': Payload(
        a_program("""
            Function("let module = 1; console.log(module)")();
            console.log('after');
            """),
        prints('1', 'after'),
        prints('1', 'after'),
    ),
    'a Function body declaring const require': Payload(
        a_program("""
            Function("const require = 2; console.log(require)")();
            console.log('after');
            """),
        prints('2', 'after'),
        prints('2', 'after'),
    ),
    'a Function body declaring let module in a file reading require after it': Payload(
        a_program("""
            Function("let module = [Date.now()]; module.push(2); console.log(module.length)")();
            console.log(typeof require);
            """),
        prints('2', 'function'),
        prints('2', 'undefined'),
    ),
    'a direct eval declaring let require in a file reading __filename after it': Payload(
        a_program("""
            eval("let require = [Date.now()]; require.push(1); console.log(require.length)");
            console.log(typeof __filename);
            """),
        prints('2', 'string'),
        prints('2', 'undefined'),
    ),
    'a Function body declaring var exports from its own value': Payload(
        a_program("""
            Function("var exports = exports || {x: 1}; console.log(exports.x);")();
            """),
        prints('1'),
        prints('1'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAPayloadReadingANameTheCommonJsWrapperBindsStaysInItsString(TestBase):

    def test_node_prints_what_each_row_pins(self):
        _node_prints_what_each_row_pins(self, A_PAYLOAD_READING_A_WRAPPER_NAME)
        _node_prints_what_each_row_pins(self, A_PAYLOAD_BINDING_A_WRAPPER_NAME_FOR_ITSELF)
        _node_prints_what_each_row_pins(
            self, A_PAYLOAD_DECLARING_A_WRAPPER_NAME_AT_THE_TOP_OF_THE_FILE
        )

    def test_each_payload_stays_as_written_where_the_file_may_be_commonjs(self):
        rows = A_PAYLOAD_READING_A_WRAPPER_NAME
        for execution in (ExecutionModel.commonjs, ExecutionModel.module):
            with self.subTest(execution.name):
                self.assertEqual(
                    {
                        label: deobfuscate_source(row.text, execution=execution)
                        for label, row in rows.items()
                    },
                    {label: printed(row.text) for label, row in rows.items()},
                )

    def test_each_program_still_prints_what_it_prints(self):
        _each_reading_still_prints(
            self,
            A_PAYLOAD_READING_A_WRAPPER_NAME,
            (Reading.COMMONJS, Reading.MODULE, Reading.ES_MODULE),
        )

    def test_a_payload_binding_the_name_for_itself_is_unpacked(self):
        rows = A_PAYLOAD_BINDING_A_WRAPPER_NAME_FOR_ITSELF
        for execution in (ExecutionModel.commonjs, ExecutionModel.module):
            unpacked = {
                label: deobfuscate_source(row.text, execution=execution)
                for label, row in rows.items()
            }
            with self.subTest(execution.name):
                self.assertEqual(
                    {label: _runs_a_string(text) for label, text in unpacked.items()},
                    {label: False for label in rows},
                )

    def test_a_program_whose_payload_binds_the_name_for_itself_still_prints_what_it_prints(self):
        _each_reading_still_prints(
            self,
            A_PAYLOAD_BINDING_A_WRAPPER_NAME_FOR_ITSELF,
            (Reading.COMMONJS, Reading.MODULE, Reading.ES_MODULE),
        )

    def test_a_payload_declaring_the_name_at_the_top_of_the_file_stays_as_written(self):
        rows = A_PAYLOAD_DECLARING_A_WRAPPER_NAME_AT_THE_TOP_OF_THE_FILE
        for execution in (ExecutionModel.commonjs, ExecutionModel.module):
            with self.subTest(execution.name):
                self.assertEqual(
                    {
                        label: deobfuscate_source(row.text, execution=execution)
                        for label, row in rows.items()
                    },
                    {label: printed(row.text) for label, row in rows.items()},
                )

    def test_a_program_whose_payload_declares_the_name_at_the_top_still_prints_what_it_prints(self):
        _each_reading_still_prints(
            self,
            A_PAYLOAD_DECLARING_A_WRAPPER_NAME_AT_THE_TOP_OF_THE_FILE,
            (Reading.COMMONJS, Reading.MODULE, Reading.ES_MODULE),
        )


#: Programs whose function, called once, declares a name the CommonJS wrapper binds, each with what
#: Node makes of it as a CommonJS file and as an ES module. Inlining the function would move the
#: declaration to the top of the file, which is the body of the function the wrapper is: a `let`,
#: `const` or `class` there redeclares a parameter, which Node refuses to compile as CommonJS and
#: runs as an ES module, and a `var` there is the parameter itself, holding what the host passed.
A_FUNCTION_CALLED_ONCE_DECLARING_A_WRAPPER_NAME = {
    'let module': Payload(
        a_program("""
            function f() { let module = [Date.now()]; module.push(2); console.log(module.length); }
            f();
            """),
        prints('2'),
        prints('2'),
    ),
    'const exports': Payload(
        a_program("""
            function f() { const exports = [Date.now()]; exports.push(2); console.log(exports.length); }
            f();
            """),
        prints('2'),
        prints('2'),
    ),
    'class require': Payload(
        a_program("""
            function f() { class require { static n = Date.now(); } console.log(typeof require, require.n > 0); }
            f();
            """),
        prints('function true'),
        prints('function true'),
    ),
    'var module, read by the file after the call': Payload(
        a_program("""
            function f() { var module = [Date.now()]; module.push(2); console.log(module.length); }
            f();
            console.log(typeof module.exports);
            """),
        prints('2', 'object'),
        (F'2{NL}', 'ReferenceError'),
    ),
    'let __dirname': Payload(
        a_program("""
            function f() { let __dirname = [Date.now()]; __dirname.push(1); console.log(__dirname.length); }
            f();
            """),
        prints('2'),
        prints('2'),
    ),
    'let module, the file reading require after the call': Payload(
        a_program("""
            function f() { let module = [Date.now()]; module.push(2); console.log(module.length); }
            f();
            console.log(typeof require);
            """),
        prints('2', 'function'),
        prints('2', 'undefined'),
    ),
    'var module, read before anything assigns it': Payload(
        a_program("""
            function f() { var module; console.log(typeof module); }
            f();
            """),
        prints('undefined'),
        prints('undefined'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFunctionDeclaringAWrapperNameStillPrintsWhatItPrints(TestBase):

    def test_node_prints_what_each_row_pins(self):
        _node_prints_what_each_row_pins(self, A_FUNCTION_CALLED_ONCE_DECLARING_A_WRAPPER_NAME)

    def test_each_program_still_prints_what_it_prints(self):
        _each_reading_still_prints(
            self,
            A_FUNCTION_CALLED_ONCE_DECLARING_A_WRAPPER_NAME,
            (Reading.COMMONJS, Reading.MODULE, Reading.ES_MODULE),
        )


#: Programs whose payload runs alike as sloppy and as strict code, or is refused under either for a
#: reason that has nothing to do with strict code, each with what Node makes of it as a CommonJS
#: file and as an ES module.
A_PAYLOAD_BOTH_READINGS_TREAT_ALIKE = {
    'a Function body reading this at its top level': Payload(
        a_program("""
            Function("console.log(this === globalThis);")();
            """),
        prints('true'),
        prints('true'),
    ),
    'a Function body reading arguments': Payload(
        a_program("""
            Function("console.log(typeof arguments, arguments.length);")();
            """),
        prints('object 0'),
        prints('object 0'),
    ),
    'an arrow in a Function body reading this': Payload(
        a_program("""
            Function("var f = () => this; console.log(f() === globalThis);")();
            """),
        prints('true'),
        prints('true'),
    ),
    'a site in a method called with a receiver': Payload(
        a_program("""
            var o = { m() { Function("console.log(this === globalThis);")(); } };
            o.m();
            """),
        prints('true'),
        prints('true'),
    ),
    'an indirect eval declaring a global': Payload(
        a_program("""
            (0, eval)("var g3 = 7;");
            console.log(globalThis.g3);
            """),
        prints('7'),
        prints('7'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAPayloadBothReadingsTreatAlikeIsDeobfuscatedAlike(TestBase):

    def test_node_prints_what_each_row_pins(self):
        _node_prints_what_each_row_pins(self, A_PAYLOAD_BOTH_READINGS_TREAT_ALIKE)

    def test_each_payload_is_deobfuscated_the_same_under_either_model(self):
        rows = A_PAYLOAD_BOTH_READINGS_TREAT_ALIKE
        self.assertEqual(
            {
                label: deobfuscate_source(row.text, execution=ExecutionModel.commonjs)
                for label, row in rows.items()
            },
            {
                label: deobfuscate_source(row.text, execution=ExecutionModel.module)
                for label, row in rows.items()
            },
        )

    def test_each_program_still_prints_what_it_prints(self):
        _each_reading_still_prints(
            self,
            A_PAYLOAD_BOTH_READINGS_TREAT_ALIKE,
            (Reading.COMMONJS, Reading.MODULE, Reading.ES_MODULE),
        )


#: Programs whose payload holds a direct `eval`, each with what Node makes of it as a CommonJS file
#: and as an ES module. The `eval` runs in the scope of the payload, which is global code; unpacked
#: into a file that runs as a module, it would run in the scope of the file.
A_PAYLOAD_HOLDING_A_DIRECT_EVAL = {
    'a Function body evaluating typeof require': Payload(
        a_program("""
            console.log(Function("return eval('typeof require')")());
            """),
        prints('undefined'),
        prints('undefined'),
    ),
    'a Function body evaluating typeof of a name the file declares': Payload(
        a_program("""
            var x = 1;
            console.log(Function("return eval('typeof x')")());
            """),
        prints('undefined'),
        prints('undefined'),
    ),
    'an indirect eval declaring a global through a direct eval': Payload(
        a_program("""
            (0, eval)("eval('var q = 1')");
            console.log(typeof globalThis.q);
            """),
        prints('number'),
        prints('number'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAPayloadHoldingADirectEvalStaysInItsString(TestBase):

    def test_node_prints_what_each_row_pins(self):
        _node_prints_what_each_row_pins(self, A_PAYLOAD_HOLDING_A_DIRECT_EVAL)

    def test_each_payload_stays_as_written_where_the_file_runs_as_a_module(self):
        rows = A_PAYLOAD_HOLDING_A_DIRECT_EVAL
        for execution in (ExecutionModel.commonjs, ExecutionModel.module):
            with self.subTest(execution.name):
                self.assertEqual(
                    {
                        label: deobfuscate_source(row.text, execution=execution)
                        for label, row in rows.items()
                    },
                    {label: printed(row.text) for label, row in rows.items()},
                )

    def test_each_program_still_prints_what_it_prints(self):
        _each_reading_still_prints(
            self,
            A_PAYLOAD_HOLDING_A_DIRECT_EVAL,
            (Reading.COMMONJS, Reading.MODULE, Reading.ES_MODULE),
        )


#: Programs whose direct `eval` declares a name the scope it runs in already declares otherwise,
#: each with what Node makes of it as a CommonJS file and as an ES module. A sloppy evaluation
#: throws a `SyntaxError` the site catches; a strict one keeps the `var` to itself.
A_DIRECT_EVAL_DECLARING_A_NAME_THE_SCOPE_DECLARES = {
    'a var the file declares with let after it': Payload(
        a_program("""
            try { eval("var q = 1;"); } catch (e) { console.log(e.name); }
            let q = 0;
            console.log(q);
            """),
        prints('SyntaxError', '0'),
        prints('0'),
    ),
    'a var the file declares as a class after it': Payload(
        a_program("""
            try { eval("var q = 1;"); } catch (e) { console.log(e.name); }
            class q {}
            console.log(typeof q);
            """),
        prints('SyntaxError', 'function'),
        prints('function'),
    ),
    'a var a function declares with let after it': Payload(
        a_program("""
            function f() { try { eval("var q = 1;"); } catch (e) { console.log(e.name); } let q = 2; return q; }
            console.log(f());
            """),
        prints('SyntaxError', '2'),
        prints('2'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestADirectEvalDeclaringANameTheScopeDeclaresStillPrintsWhatItPrints(TestBase):

    def test_node_prints_what_each_row_pins(self):
        _node_prints_what_each_row_pins(self, A_DIRECT_EVAL_DECLARING_A_NAME_THE_SCOPE_DECLARES)

    def test_each_program_still_prints_what_it_prints(self):
        _each_reading_still_prints(
            self,
            A_DIRECT_EVAL_DECLARING_A_NAME_THE_SCOPE_DECLARES,
            (Reading.COMMONJS, Reading.MODULE, Reading.ES_MODULE),
        )


#: Packed programs asking `typeof` of a key the accessor object answers, each with what Node makes
#: of it as a CommonJS file and as an ES module. A getter returning a name throws where nothing
#: binds the name, which `typeof` of the bare name does not.
A_PACKED_TYPEOF_OF_A_KEY = {
    'a getter returning a name nothing binds': Payload(
        a_program("""
            Function("p", "console.log(typeof p.g)")({ get g() { return someGlobal; } });
            """),
        ('', 'ReferenceError'),
        ('', 'ReferenceError'),
    ),
    'a getter returning require': Payload(
        a_program("""
            Function("p", "console.log(typeof p.r)")({ get r() { return require; } });
            """),
        prints('function'),
        ('', 'ReferenceError'),
    ),
    'a getter returning typeof of a name nothing binds': Payload(
        a_program("""
            Function("p", "console.log(p.t)")({ get t() { return typeof someGlobal; } });
            """),
        prints('undefined'),
        prints('undefined'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAPackedTypeofOfAKeyStillThrowsWhereItsGetterThrows(TestBase):

    def test_node_prints_what_each_row_pins(self):
        _node_prints_what_each_row_pins(self, A_PACKED_TYPEOF_OF_A_KEY)

    def test_each_program_still_prints_what_it_prints(self):
        _each_reading_still_prints(
            self,
            A_PACKED_TYPEOF_OF_A_KEY,
            (Reading.COMMONJS, Reading.MODULE, Reading.ES_MODULE),
        )


#: Packed programs writing a global through the accessor object with an operator that reads it as
#: well, each with what Node makes of it as a CommonJS file and as an ES module. The global's getter
#: and setter are written at the top of the file, so the setter's write is as strict as the file.
A_PACKED_COMPOUND_WRITE_ON_A_GLOBAL = {
    'a compound write, an update and a logical assignment': Payload(
        a_program("""
            Function("p", "p.k = 1; p.k += 15; p.k++; p.k ||= 0; console.log(p.k, counter);")(
              { get k() { return counter; }, set k(v) { return counter = v; } }
            );
            """),
        prints('17 17'),
        ('', 'ReferenceError'),
    ),
    'a compound write on a global nothing has assigned yet': Payload(
        a_program("""
            Function("p", "p.k += 1; console.log('after');")({ get k() { return counter; }, set k(v) { return counter = v; } });
            """),
        ('', 'ReferenceError'),
        ('', 'ReferenceError'),
    ),
    'a compound write whose right side writes the global first': Payload(
        a_program("""
            Function("p", "p.k = 1; p.k += (p.k = 10, 1); console.log(p.k);")(
              { get k() { return counter; }, set k(v) { return counter = v; } }
            );
            """),
        prints('2'),
        ('', 'ReferenceError'),
    ),
    'a delete through the accessor object': Payload(
        a_program("""
            Function("p", "console.log(delete p.k, p.k);")({ get k() { return counter; }, set k(v) { return counter = v; } });
            """),
        prints('true undefined'),
        prints('true undefined'),
    ),
    'a compound write to an optional chain': Payload(
        a_program("""
            globalThis.counter = 0;
            try {
              Function("p", "p?.k += 1")({ get k() { return counter; }, set k(v) { return counter = v; } });
            } catch (e) {
              console.log(e.name);
            }
            console.log('end');
            """),
        prints('SyntaxError', 'end'),
        prints('SyntaxError', 'end'),
    ),
    'a compound write to an array literal holding the key': Payload(
        a_program("""
            globalThis.counter = 0;
            try {
              Function("p", "[p.k] += 1")({ get k() { return counter; }, set k(v) { return counter = v; } });
            } catch (e) {
              console.log(e.name);
            }
            console.log('end');
            """),
        prints('SyntaxError', 'end'),
        prints('SyntaxError', 'end'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAPackedCompoundWriteOnAGlobalStillPrintsWhatItPrints(TestBase):

    def test_node_prints_what_each_row_pins(self):
        _node_prints_what_each_row_pins(self, A_PACKED_COMPOUND_WRITE_ON_A_GLOBAL)

    def test_each_program_still_prints_what_it_prints(self):
        _each_reading_still_prints(
            self,
            A_PACKED_COMPOUND_WRITE_ON_A_GLOBAL,
            (Reading.COMMONJS, Reading.MODULE, Reading.ES_MODULE),
        )


#: Packed programs whose access the bare name the accessor object answers with would not
#: reproduce, each with what Node makes of it as a CommonJS file and as an ES module.
A_PACKED_ACCESS_THE_BARE_NAME_DOES_NOT_REPRODUCE = {
    'a parameter text naming two parameters': Payload(
        a_program("""
            Function("a,b", "console.log(typeof a, typeof b)")({});
            """),
        prints('object undefined'),
        prints('object undefined'),
    ),
    'a call through a getter returning eval': Payload(
        a_program("""
            Function("p", "var y = 2; console.log(p.e('typeof y'))")({ get e() { return eval; } });
            """),
        prints('undefined'),
        prints('undefined'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAPackedAccessTheBareNameDoesNotReproduceStillPrintsWhatItPrints(TestBase):

    def test_node_prints_what_each_row_pins(self):
        _node_prints_what_each_row_pins(self, A_PACKED_ACCESS_THE_BARE_NAME_DOES_NOT_REPRODUCE)

    def test_each_program_still_prints_what_it_prints(self):
        _each_reading_still_prints(
            self,
            A_PACKED_ACCESS_THE_BARE_NAME_DOES_NOT_REPRODUCE,
            (Reading.COMMONJS, Reading.MODULE, Reading.ES_MODULE),
        )


#: The packer's output for an eleven-line fizzbuzz that reads no global it would map: the accessor
#: object is empty.
PACKED_FIZZBUZZ = (
    r'Function("ZvYyC4L","function fizzbuzz(limit){var lines=[];for(var i=1;i<=limit;i++){var '
    r'line=\"\";if(i%3===0){line+=\"Fizz\"}if(i%5===0){line+=\"Buzz\"}lines[\"push\"](line||St'
    r'ring(i))}return lines[\"join\"](\", \")}return console[\"log\"](\"FizzBuzz: \"+fizzbuzz('
    r'15));")({});'
)

#: The packer's output for the same fizzbuzz run on an undeclared global it assigns and adds to,
#: printed beside what `typeof module` says and a name `require("path")` computes: getters, a
#: setter, and a getter answering `typeof` for the program.
PACKED_GLOBALS = (
    r'Function("ym9Tun8","function fizzbuzz(limit){var lines=[];for(var i=1;i<=limit;i++){var '
    r'line=\"\";if(i%3===0){line+=\"Fizz\"}if(i%5===0){line+=\"Buzz\"}lines[\"push\"](line||St'
    r'ring(i))}return lines[\"join\"](\", \")}ym9Tun8[\"KADlpg\"]=0;ym9Tun8[\"KADlpg\"]+=15;va'
    r'r kind=ym9Tun8[\"FCHW63\"]===\"object\"?\"commonjs\":\"other\";return console[\"log\"]('
    r'\"FizzBuzz: \"+fizzbuzz(ym9Tun8[\"KADlpg\"]),kind,ym9Tun8[\"VM9Zxy\"](\"path\")[\"basena'
    r'me\"](\"a/b.js\"));")({get"KADlpg"(){return counter},set"KADlpg"(ym9Tun8){return counter'
    r'=ym9Tun8},get"VM9Zxy"(){return require},get"FCHW63"(){return typeof module}});'
)

#: The program `PACKED_GLOBALS` packs, as `refinery.js` writes it once unpacked.
PACKED_GLOBALS_UNPACKED = inspect.cleandoc(
    """
    function fizzbuzz(limit) {
      var lines = [];
      for (var i = 1; i <= limit; i++) {
        var line = "";
        if (i % 3 === 0) {
          line += "Fizz";
        }
        if (i % 5 === 0) {
          line += "Buzz";
        }
        lines.push(line || String(i));
      }
      return lines.join(", ");
    }
    counter = 0;
    counter += 15;
    console.log("FizzBuzz: " + fizzbuzz(counter), typeof module === "object" ? "commonjs" : "other", require("path").basename("a/b.js"));
    """
)


class TestThePackersOwnOutputIsUnpacked(TestBase):
    """
    The packer's own output for two small programs, deobfuscated as an analyst runs `refinery.js` on
    a Node script and read as text only. Each program writes through the accessor object only where
    the accessors stand, at the top of the file, so it unpacks whether the file is known to be
    CommonJS or may be an ES module as well.
    """

    def _deobfuscated(self, source: str, *switches: str) -> str:
        return source.encode('utf8') | js.assemble(*switches, '-e', 'node') | str

    def test_a_program_reading_no_global_is_recovered_as_the_line_it_prints(self):
        printed_line = (
            'console.log(\'FizzBuzz: 1, 2, Fizz, 4, Buzz, Fizz, 7, 8, Fizz, Buzz, 11, Fizz, 13, 14,'
            ' FizzBuzz\');'
        )
        for switch in ('-c', '-m'):
            with self.subTest(switch):
                self.assertEqual(self._deobfuscated(PACKED_FIZZBUZZ, switch), printed_line)

    def test_a_program_reading_and_writing_globals_is_recovered(self):
        for switch in ('-c', '-m'):
            with self.subTest(switch):
                self.assertEqual(
                    self._deobfuscated(PACKED_GLOBALS, switch), PACKED_GLOBALS_UNPACKED
                )
