"""
SECURITY: every program here is hand-authored in this file and benign. No sample and no stored
obfuscator fixture may be fed to this.
"""
from __future__ import annotations

import inspect
import unittest

from test import TestBase, backlog, opportunity
from test.lib.scripts.js.analysis.differential import node_executable
from test.lib.scripts.js.ledger import (
    Program,
    Reading,
    a_program,
    folded,
    printed,
    prints,
)


def _still_answered(rows: dict[str, Program]) -> dict[str, tuple]:
    return {label: row.read() for label, row in rows.items()}


def _as_it_answers_them(rows: dict[str, Program]) -> dict[str, tuple]:
    return {label: row.required() for label, row in rows.items()}


#: In sloppy code, a function declared in a block is also copied into a `var` of its name in the
#: enclosing function where the declaration runs (Annex B.3.3). Each condition that suppresses the
#: copy leaves the enclosing name holding what it held.
A_BLOCK_FUNCTION_THE_PROGRAM_STILL_ANSWERS_FOR = {
    'a call after the block': Program(
        a_program("""
            function outer() {
              { function W() { return 1; } }
              console.log(W());
            }
            outer();
            """),
        prints('1'),
    ),
    'a call inside the block': Program(
        a_program("""
            function outer() {
              { function W() { return 1; } console.log(W()); }
            }
            outer();
            """),
        prints('1'),
    ),
    'a lexical binding of the name suppresses the copy': Program(
        a_program("""
            function outer() {
              let W = 7;
              { function W() { return 1; } }
              console.log(W);
            }
            outer();
            """),
        prints('7'),
    ),
    'a parameter of the name suppresses the copy': Program(
        a_program("""
            function outer(W) {
              { function W() { return 1; } }
              console.log(W);
            }
            outer('outer');
            """),
        prints('outer'),
    ),
    'a destructuring catch parameter suppresses the copy': Program(
        a_program("""
            function outer() {
              try { throw { W: 7 }; } catch ({ W }) {
                { function W() { return 1; } }
                console.log(W);
              }
              console.log(typeof W);
            }
            outer();
            """),
        prints('7', 'undefined'),
    ),
    'a simple catch parameter is what the block reads': Program(
        a_program("""
            function outer() {
              try { throw 7; } catch (W) {
                { function W() { return 1; } }
                console.log(W);
              }
              console.log(typeof W);
            }
            outer();
            """),
        prints('7', 'function'),
    ),
    'the copy takes the value the block name holds where it runs': Program(
        a_program("""
            function outer() {
              var W = 7;
              { W = 9; function W() { return 1; } }
              console.log(W);
            }
            outer();
            """),
        prints('9'),
    ),
    'a label between the block and the declaration is transparent': Program(
        a_program("""
            function outer() {
              { lab: function W() { return 1; } }
              console.log(typeof W);
            }
            outer();
            """),
        prints('function'),
    ),
    'the name arguments has its creation suppressed and its copy run': Program(
        a_program("""
            function outer() {
              { function arguments() { return 1; } }
              console.log(typeof arguments);
            }
            outer(1);
            """),
        prints('function'),
    ),
    'a block no branch takes runs no copy': Program(
        a_program("""
            function outer(c) {
              if (c) { function W() { return 1; } }
              console.log(typeof W);
            }
            outer(0);
            """),
        prints('undefined'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestABlockFunctionIsWhereItsModeAndItsPositionPutIt(TestBase):

    def test_a_block_function_the_program_answers_for_is_answered_the_same_way(self):
        rows = A_BLOCK_FUNCTION_THE_PROGRAM_STILL_ANSWERS_FOR
        self.assertEqual(_still_answered(rows), _as_it_answers_them(rows))


#: Annex B creates no `var` named `arguments` where the enclosing function or the CommonJS wrapper
#: of the file already has an arguments object, but the copy still runs where the declaration does
#: and replaces that object.
A_BLOCK_FUNCTION_NAMED_ARGUMENTS = {
    'a read after the block': Program(
        a_program("""
            function outer() {
              { function arguments() { return 1; } }
              console.log(typeof arguments);
            }
            outer(1);
            """),
        prints('function'),
        Reading.COMMONJS,
    ),
    'a read of the object before the block': Program(
        a_program("""
            function outer(a) {
              console.log(arguments.length);
              { function arguments() { return 1; } }
              console.log(typeof arguments, arguments.length);
            }
            outer(1, 2);
            """),
        prints('2', 'function 0'),
        Reading.COMMONJS,
    ),
    'a block holding another statement': Program(
        a_program("""
            function outer() {
              { function arguments() { return 1; } var z = 1; }
              console.log(typeof arguments, z);
            }
            outer(1);
            """),
        prints('function 1'),
        Reading.COMMONJS,
    ),
    'a parameter with a default': Program(
        a_program("""
            function outer(a = 1) {
              { function arguments() { return 2; } }
              console.log(typeof arguments, a);
            }
            outer();
            """),
        prints('function 1'),
        Reading.COMMONJS,
    ),
    'a mapped parameter written after the copy': Program(
        a_program("""
            function outer(a) {
              { function arguments() { return 2; } }
              a = 5;
              console.log(arguments[0], a);
            }
            outer(1);
            """),
        prints('undefined 5'),
        Reading.COMMONJS,
    ),
    'an element read at the top of the file': Program(
        a_program("""
            exports = 1;
            { function arguments() {} }
            console.log(arguments[0]);
            """),
        prints('undefined'),
        Reading.COMMONJS,
    ),
    'a type read at the top of the file': Program(
        a_program("""
            { function arguments() {} }
            console.log(typeof arguments);
            """),
        prints('function'),
        Reading.COMMONJS,
    ),
    'a branch taken on the second call only': Program(
        a_program("""
            function outer(c) {
              if (c) { function arguments() { return 1; } }
              console.log(typeof arguments);
            }
            outer(0);
            outer(1);
            """),
        prints('object', 'function'),
        Reading.COMMONJS,
    ),
    'an arrow function, which has no object of its own': Program(
        a_program("""
            function outer() {
              var f = () => {
                { function arguments() { return 1; } }
                return typeof arguments;
              };
              console.log(f(), typeof arguments);
            }
            outer(1);
            """),
        prints('function object'),
        Reading.COMMONJS,
    ),
    'the copy called': Program(
        a_program("""
            function outer() {
              { function arguments() { return 'called'; } }
              console.log(arguments());
            }
            outer();
            """),
        prints('called'),
        Reading.COMMONJS,
    ),
    'a block holding an unread var': Program(
        a_program("""
            function outer() {
              { function arguments() { return 1; } var z = 1; }
              console.log(typeof arguments);
            }
            outer(1);
            """),
        prints('function'),
        Reading.COMMONJS,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestABlockFunctionNamedArgumentsReplacesTheObject(TestBase):

    def test_a_block_function_named_arguments_is_answered_the_way_node_runs_it(self):
        rows = A_BLOCK_FUNCTION_NAMED_ARGUMENTS
        self.assertEqual(_still_answered(rows), _as_it_answers_them(rows))


A_PARAMETER_DEFAULT_READING_PAST_THE_BODY = {
    'a call in a default': Program(
        a_program("""
            function g() { return 1; }
            function f(x = g()) { function g() { return 2; } return x; }
            console.log(f());
            """),
        prints('1'),
    ),
    'a read in a default': Program(
        a_program("""
            var v = 1;
            function f(x = v) { var v = 2; return x; }
            console.log(f());
            """),
        prints('1'),
    ),
    'a wrapper a default names': Program(
        a_program("""
            function W() { W = function () {}; }
            function f(x = W(console.log(1))) { var W; return typeof x; }
            W(console.log(2));
            f();
            """),
        prints('2', '1'),
    ),
    'an arrow default': Program(
        a_program("""
            var v = 1;
            var f = (x = v) => { var v = 2; return x; };
            console.log(f());
            """),
        prints('1'),
    ),
    'a class method default': Program(
        a_program("""
            var v = 1;
            class C { m(x = v) { var v = 2; return x; } }
            console.log(new C().m());
            """),
        prints('1'),
    ),
    'a shorthand method default': Program(
        a_program("""
            var v = 1;
            var o = { m(x = v) { var v = 2; return x; } };
            console.log(o.m());
            """),
        prints('1'),
    ),
    'a destructured default': Program(
        a_program("""
            var v = 1;
            function f({ x = v } = {}) { var v = 2; return x; }
            console.log(f());
            """),
        prints('1'),
    ),
    'a generator default': Program(
        a_program("""
            var v = 1;
            function* f(x = v) { var v = 2; yield x; }
            console.log(f().next().value);
            """),
        prints('1'),
    ),
    'a closure a default holds': Program(
        a_program("""
            var v = 1;
            function f(g = function () { return v; }) { var v = 2; return g(); }
            console.log(f());
            """),
        prints('1'),
    ),
    'a readable eval in a default': Program(
        a_program("""
            var v = 1;
            function f(x = eval('v')) { var v = 2; return x; }
            console.log(f());
            """),
        prints('1'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAParameterDefaultReadsPastTheBody(TestBase):

    def test_a_parameter_default_reads_the_scope_around_the_function(self):
        rows = A_PARAMETER_DEFAULT_READING_PAST_THE_BODY
        self.assertEqual(_still_answered(rows), _as_it_answers_them(rows))


A_WRAPPER_A_DEFAULT_AND_A_BODY_BOTH_NAME = {
    'a call from a default and one from the body': (
        Program(
            a_program("""
                function W() { W = function () {}; }
                function f(x = W(console.log(1))) { W(console.log(3)); return typeof x; }
                W(console.log(2));
                f();
                """),
            prints('2', '1', '3'),
        ),
        inspect.cleandoc(
            """
            function f(x = (console.log(1), void 0)) {
              console.log(3);
              return typeof x;
            }
            console.log(2);
            f();
            """
        ),
    ),
    'a call from a default alone': (
        Program(
            a_program("""
                function W() { W = function () {}; }
                function f(x = W(console.log(1))) { return typeof x; }
                f();
                """),
            prints('1'),
        ),
        inspect.cleandoc(
            """
            function f(x = (console.log(1), void 0)) {
              return typeof x;
            }
            f();
            """
        ),
    ),
}


class TestAWrapperADefaultNamesIsStillExpanded(TestBase):

    def test_each_call_a_default_makes_is_expanded(self):
        self.assertEqual(
            {
                label: folded(row.text)
                for label, (row, _) in A_WRAPPER_A_DEFAULT_AND_A_BODY_BOTH_NAME.items()
            },
            {
                label: text
                for label, (_, text) in A_WRAPPER_A_DEFAULT_AND_A_BODY_BOTH_NAME.items()
            },
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_each_program_prints_what_it_printed(self):
        rows = {
            label: row for label, (row, _) in A_WRAPPER_A_DEFAULT_AND_A_BODY_BOTH_NAME.items()}
        self.assertEqual(_still_answered(rows), _as_it_answers_them(rows))


A_BODY_VAR_OF_A_PARAMETERS_NAME = a_program("""
    function f(x = 1) { console.log(x); var x = 5; console.log(x); }
    f();
    """)


class TestABodyVarOfAParametersNameIsReadFromTheText(TestBase):

    def test_the_program_comes_back_as_it_was_written_or_folded_to_what_it_prints(self):
        self.assertIn(
            folded(A_BODY_VAR_OF_A_PARAMETERS_NAME),
            (
                inspect.cleandoc(
                    """
                    function f(x = 1) {
                      console.log(x);
                      var x = 5;
                      console.log(x);
                    }
                    f();
                    """
                ),
                inspect.cleandoc(
                    """
                    console.log(1);
                    console.log(5);
                    """
                ),
            ),
        )

    @opportunity
    def test_the_program_is_folded_to_what_it_prints(self):
        self.assertEqual(
            folded(A_BODY_VAR_OF_A_PARAMETERS_NAME),
            inspect.cleandoc(
                """
                console.log(1);
                console.log(5);
                """
            ),
        )


A_TOP_LEVEL_THIS_REACHING_THE_GLOBAL_OBJECT = {
    'a var the top level declares': Program(
        a_program("""
            var q = function (a) { console.log('q', a); };
            this.q(1);
            """),
        prints('q 1'),
        Reading.SCRIPT,
    ),
    'a wrapper the top level declares': Program(
        a_program("""
            function W() { W = function () {}; }
            W(console.log(1));
            this.W(2);
            console.log('end');
            """),
        prints('1', 'end'),
        Reading.SCRIPT,
    ),
    'an arrow at the top level': Program(
        a_program("""
            var q = function (a) { console.log('q', a); };
            (() => { this.q(1); })();
            """),
        prints('q 1'),
        Reading.SCRIPT,
    ),
    'a global property written beside the read': Program(
        a_program("""
            globalThis.q = function (a) { console.log('q', a); };
            this.q(1);
            """),
        prints('q 1'),
        Reading.SCRIPT,
    ),
    'a computed write through the top-level this': Program(
        a_program("""
            var q = 1;
            this['q'] = 2;
            console.log(q);
            """),
        prints('2'),
        Reading.SCRIPT,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestATopLevelThisNamesTheGlobalObject(TestBase):

    def test_a_declaration_a_top_level_this_reads_is_still_read(self):
        rows = A_TOP_LEVEL_THIS_REACHING_THE_GLOBAL_OBJECT
        self.assertEqual(_still_answered(rows), _as_it_answers_them(rows))


class TestTheDeclarationATopLevelThisReadsIsKept(TestBase):

    def test_each_declaration_a_this_reads_is_kept(self):
        rows = A_TOP_LEVEL_THIS_REACHING_THE_GLOBAL_OBJECT
        self.assertEqual(
            {label: folded(rows[label].text) for label in [
                'a var the top level declares',
                'a global property written beside the read',
                'a computed write through the top-level this',
            ]},
            {
                'a var the top level declares': inspect.cleandoc(
                    """
                    var q = function(a) {
                      console.log('q', a);
                    };
                    this.q(1);
                    """
                ),
                'a global property written beside the read': inspect.cleandoc(
                    """
                    globalThis.q = function(a) {
                      console.log('q', a);
                    };
                    this.q(1);
                    """
                ),
                'a computed write through the top-level this': inspect.cleandoc(
                    """
                    var q = 1;
                    this.q = 2;
                    console.log(q);
                    """
                ),
            },
        )


#: Strict code binds a function declared in a block only in that block. Sloppy code also creates a
#: `var` of its name at the entry of the enclosing function, so a call before the block reads
#: `undefined`. A generator or an async function is never copied into that `var`, and a plain
#: function is not copied past a block that binds a generator or an async function of its name.
A_FUNCTION_DECLARED_INSIDE_A_BLOCK = {
    'a module': Program(
        a_program("""
            function outer() {
              { function W() { return 1; } }
              try { console.log(W()); } catch (e) { console.log('threw'); }
            }
            outer();
            export {};
            """),
        prints('threw'),
        Reading.ES_MODULE,
    ),
    'a script saying so': Program(
        a_program("""
            'use strict';
            function outer() {
              { function W() { return 1; } }
              try { console.log(W()); } catch (e) { console.log('threw'); }
            }
            outer();
            """),
        prints('threw'),
    ),
    'a function body saying so': Program(
        a_program("""
            function outer() {
              'use strict';
              { function W() { return 1; } }
              try { console.log(W()); } catch (e) { console.log('threw'); }
            }
            outer();
            """),
        prints('threw'),
    ),
    'a sloppy call before the block': Program(
        a_program("""
            function outer() {
              try { console.log(W()); } catch (e) { console.log('threw'); }
              { function W() { return 1; } }
            }
            outer();
            """),
        prints('threw'),
    ),
    'a sloppy generator read after the block': Program(
        a_program("""
            function outer() {
              var W = 7;
              function inner() {
                { function* W() { yield 1; } }
                return W;
              }
              console.log(inner());
            }
            outer();
            """),
        prints('7'),
    ),
    'a sloppy async function read after the block': Program(
        a_program("""
            function outer() {
              var W = 7;
              function inner() {
                { async function W() { return 1; } }
                return W;
              }
              console.log(inner());
            }
            outer();
            """),
        prints('7'),
    ),
    'a sloppy function in a block inside the block of a generator of its name': Program(
        a_program("""
            function outer() {
              { function* W() { yield 1; } { function W() { return 1; } } }
              try { return W(); } catch (e) { return e.constructor.name; }
            }
            console.log(outer());
            """),
        prints('ReferenceError'),
    ),
    'a sloppy function in a block inside the block of an async function of its name': Program(
        a_program("""
            function outer() {
              { async function W() { return 1; } { function W() { return 2; } } }
              try { return W(); } catch (e) { return e.constructor.name; }
            }
            console.log(outer());
            """),
        prints('ReferenceError'),
    ),
    'a sloppy function in a block beside a generator of its name in the body': Program(
        a_program("""
            function outer() {
              function* W() { yield 1; }
              { function W() { return 1; } }
              return W();
            }
            console.log(outer());
            """),
        prints('1'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFunctionDeclaredInsideABlockIsDeclaredInsideIt(TestBase):

    def test_a_block_function_is_read_from_where_the_language_binds_it(self):
        rows = A_FUNCTION_DECLARED_INSIDE_A_BLOCK
        self.assertEqual(_still_answered(rows), _as_it_answers_them(rows))


A_DECLARATION_A_DEAD_BLOCK_HOLDS = {
    'a function no branch declares': Program(
        a_program("""
            if (0) { function W() { return 1; } }
            console.log(W);
            """),
        prints('undefined'),
    ),
    'a var no branch declares': Program(
        a_program("""
            if (0) { var v = 1; }
            console.log(v);
            """),
        prints('undefined'),
    ),
    'a function that is the whole of an if clause': Program(
        a_program("""
            function outer() {
              if (0) function W() { return 1; }
              console.log(W);
            }
            outer();
            """),
        prints('undefined'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestADeclarationADeadBlockHoldsIsStillDeclared(TestBase):

    def test_a_declaration_a_dead_block_holds_is_still_read(self):
        rows = A_DECLARATION_A_DEAD_BLOCK_HOLDS
        self.assertEqual(_still_answered(rows), _as_it_answers_them(rows))


class TestTheDeclarationsADeadBlockHeldAreKept(TestBase):

    def test_each_dead_block_at_the_top_of_the_script_leaves_the_names_it_declared(self):
        rows = A_DECLARATION_A_DEAD_BLOCK_HOLDS
        self.assertEqual(
            {
                label: folded(rows[label].text)
                for label in ['a function no branch declares', 'a var no branch declares']
            },
            {
                'a function no branch declares': 'var W;\nconsole.log(W);',
                'a var no branch declares': 'var v;\nconsole.log(v);',
            },
        )

    @backlog
    def test_a_dead_clause_in_a_function_leaves_its_name_in_the_function_or_the_read_folded(self):
        self.assertIn(
            folded(A_DECLARATION_A_DEAD_BLOCK_HOLDS['a function that is the whole of an if clause'].text),
            (
                inspect.cleandoc(
                    """
                    function outer() {
                      var W;
                      console.log(W);
                    }
                    outer();
                    """
                ),
                'console.log(void 0);',
            ),
        )

    @opportunity
    def test_a_dead_clause_in_a_function_leaves_the_read_folded(self):
        self.assertEqual(
            folded(A_DECLARATION_A_DEAD_BLOCK_HOLDS['a function that is the whole of an if clause'].text),
            'console.log(void 0);',
        )


A_CALL_TO_A_BLOCK_FUNCTION_THAT_WRITES_PAST_ITS_BLOCK = {
    'a call in a loop body': Program(
        a_program("""
            var v = 1;
            for (let i = 0; i < 1; i++) { function f() { v = 2; } f(); }
            console.log(v);
            """),
        prints('2'),
    ),
    'a call in a plain block': Program(
        a_program("""
            var v = 1;
            { function m() { v = 2; } m(); }
            console.log(v);
            """),
        prints('2'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestACallWhoseCalleeCannotBeValuedStillWrites(TestBase):

    def test_a_write_from_a_block_function_still_reaches_the_name_outside(self):
        rows = A_CALL_TO_A_BLOCK_FUNCTION_THAT_WRITES_PAST_ITS_BLOCK
        self.assertEqual(_still_answered(rows), _as_it_answers_them(rows))


A_CALL_TO_A_BLOCK_FUNCTION = {
    'a call after the block': (
        a_program("""
            function outer() {
              { function W() { return 1; } }
              console.log(W());
            }
            outer();
            """),
        'console.log(1);',
    ),
    'a value taken out of the block': (
        a_program("""
            function outer() {
              { function W() { return 1; } }
              var g = W;
              console.log(g());
            }
            outer();
            """),
        'console.log(1);',
    ),
}


A_CALL_INSIDE_THE_BLOCK_OF_A_BLOCK_FUNCTION = a_program("""
    function outer() {
      { function W() { return 1; } console.log(W()); }
    }
    outer();
    """)


A_CALL_BEFORE_THE_COPY_OF_A_BLOCK_FUNCTION_RUNS = a_program("""
    function outer() {
      try { console.log(W()); } catch (e) { console.log('threw'); }
      { function W() { return 1; } }
    }
    outer();
    """)


class TestACallToABlockFunctionIsFoldedWhereTheCopyHasRun(TestBase):

    def test_each_call_is_folded_where_the_copy_has_run(self):
        self.assertEqual(
            {
                label: folded(program)
                for label, (program, _) in A_CALL_TO_A_BLOCK_FUNCTION.items()
            },
            {label: text for label, (_, text) in A_CALL_TO_A_BLOCK_FUNCTION.items()},
        )

    @opportunity
    def test_a_call_inside_the_block_is_folded_and_the_block_around_it_removed(self):
        self.assertEqual(folded(A_CALL_INSIDE_THE_BLOCK_OF_A_BLOCK_FUNCTION), 'console.log(1);')

    @backlog
    def test_a_call_before_the_copy_runs_comes_back_as_it_was_written_or_folded_to_what_it_prints(self):
        self.assertIn(
            folded(A_CALL_BEFORE_THE_COPY_OF_A_BLOCK_FUNCTION_RUNS),
            (
                printed(A_CALL_BEFORE_THE_COPY_OF_A_BLOCK_FUNCTION_RUNS),
                "console.log('threw');",
            ),
        )

    @opportunity
    def test_a_call_before_the_copy_runs_is_folded_to_what_it_prints(self):
        self.assertEqual(folded(A_CALL_BEFORE_THE_COPY_OF_A_BLOCK_FUNCTION_RUNS), "console.log('threw');")


A_PARAMETER_SCOPE_THE_PROGRAM_STILL_ANSWERS_FOR = {
    'a bare var of a parameter name keeps the argument': Program(
        a_program("""
            function f(x = 1) { console.log(x); var x; console.log(x); }
            f();
            """),
        prints('1', '1'),
    ),
    'a var of a parameter name is written where its initializer runs': Program(
        a_program("""
            function f(x = 1) { console.log(x); var x = 5; console.log(x); }
            f();
            """),
        prints('1', '5'),
    ),
    'a default reading a later parameter throws': Program(
        a_program("""
            function f(a = b, b = 2) { return a; }
            try { console.log(f()); } catch (e) { console.log(e.constructor.name); }
            """),
        prints('ReferenceError'),
    ),
    'a lexical binding beside the parameters is its own': Program(
        a_program("""
            function f(x = 5) { let args = [x, 1]; return args; }
            console.log(JSON.stringify(f()));
            """),
        prints('[5,1]'),
    ),
    'a default reads the name of its own function expression': Program(
        a_program("""
            var f = function g(x = g) { return typeof x; };
            console.log(f());
            """),
        prints('function'),
    ),
    'a body var of the name of its own function expression is undefined': Program(
        a_program("""
            var f = function g() { var g; return typeof g; };
            console.log(f());
            """),
        prints('undefined'),
    ),
    'a parameter spelling the name of its own function expression wins': Program(
        a_program("""
            var f = function g(g) { return g; };
            console.log(f(7));
            """),
        prints('7'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAParameterAndItsBodyAnswerForOneName(TestBase):

    def test_a_parameter_scope_the_program_answers_for_is_answered_the_same_way(self):
        rows = A_PARAMETER_SCOPE_THE_PROGRAM_STILL_ANSWERS_FOR
        self.assertEqual(_still_answered(rows), _as_it_answers_them(rows))


THE_RECEIVER_A_POSITION_OF_A_SCRIPT_HOLDS = {
    'the top level': Program(
        a_program('console.log(this === globalThis);'),
        prints('true'),
        Reading.SCRIPT,
    ),
    'a strict top level': Program(
        a_program("""
            'use strict';
            console.log(this === globalThis);
            """),
        prints('true'),
        Reading.SCRIPT,
    ),
    'an arrow at the top level': Program(
        a_program('(() => { console.log(this === globalThis); })();'),
        prints('true'),
        Reading.SCRIPT,
    ),
    'an arrow inside an arrow': Program(
        a_program('(() => (() => { console.log(this === globalThis); })())();'),
        prints('true'),
        Reading.SCRIPT,
    ),
    'a default of an arrow': Program(
        a_program('((a = (this === globalThis)) => { console.log(a); })();'),
        prints('true'),
        Reading.SCRIPT,
    ),
    'an arrow in an object literal': Program(
        a_program("""
            var o = { m: () => this === globalThis };
            console.log(o.m());
            """),
        prints('true'),
        Reading.SCRIPT,
    ),
    'a computed key of a class': Program(
        a_program('class C { [(console.log(this === globalThis), "k")]() {} }'),
        prints('true'),
        Reading.SCRIPT,
    ),
    'an extends clause of a class': Program(
        a_program('class C extends (console.log(this === globalThis), Object) {}'),
        prints('true'),
        Reading.SCRIPT,
    ),
    'a sloppy call with no receiver': Program(
        a_program("""
            function f() { console.log(this === globalThis); }
            f();
            """),
        prints('true'),
        Reading.SCRIPT,
    ),
    'a method of an object literal': Program(
        a_program("""
            var o = { m() { return this === globalThis; } };
            console.log(o.m());
            """),
        prints('false'),
        Reading.SCRIPT,
    ),
    'a getter of an object literal': Program(
        a_program("""
            var o = { get g() { return this === globalThis; } };
            console.log(o.g);
            """),
        prints('false'),
        Reading.SCRIPT,
    ),
    'a static block of a class': Program(
        a_program('class C { static { console.log(this === globalThis); } }'),
        prints('false'),
        Reading.SCRIPT,
    ),
    'a field initializer of a class': Program(
        a_program("""
            class C { f = console.log(this === globalThis); }
            new C();
            """),
        prints('false'),
        Reading.SCRIPT,
    ),
    'a strict call with no receiver': Program(
        a_program("""
            function f() { 'use strict'; console.log(this === undefined); }
            f();
            """),
        prints('true'),
        Reading.SCRIPT,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestTheReceiverAPositionOfAScriptHolds(TestBase):

    def test_each_position_reports_the_receiver_it_holds(self):
        rows = THE_RECEIVER_A_POSITION_OF_A_SCRIPT_HOLDS
        self.assertEqual(_still_answered(rows), _as_it_answers_them(rows))


A_REMOVAL_A_COMPUTED_WRITE_THROUGH_THIS_STANDS_BESIDE = a_program("""
    var z = 1;
    var k = 'q';
    this[k] = 2;
    console.log(3);
    """)


A_TOP_LEVEL_DECLARATION_NOTHING_IN_THE_FILE_NAMES = a_program("""
    var q = function (a) { console.log(a); };
    console.log(1);
    """)


class TestARemovalTheGlobalObjectFixGivesUp(TestBase):

    def test_the_removals_a_computed_write_stopped_happen_again_once_its_key_folds(self):
        self.assertEqual(
            folded(A_REMOVAL_A_COMPUTED_WRITE_THROUGH_THIS_STANDS_BESIDE),
            inspect.cleandoc(
                """
                this.q = 2;
                console.log(3);
                """
            ),
        )

    def test_a_top_level_declaration_nothing_names_is_still_removed(self):
        self.assertEqual(
            folded(A_TOP_LEVEL_DECLARATION_NOTHING_IN_THE_FILE_NAMES),
            'console.log(1);',
        )


A_DECLARATION_A_TAKEN_BRANCH_HOLDS = {
    'a block function': Program(
        a_program("""
            function outer() {
              console.log(typeof W);
              if (1) { function W() { return 1; } }
              console.log(typeof W);
            }
            outer();
            """),
        prints('undefined', 'function'),
    ),
    'a function that is the whole of the clause': Program(
        a_program("""
            function outer() {
              console.log(typeof W);
              if (1) function W() { return 1; }
              console.log(typeof W);
            }
            outer();
            """),
        prints('undefined', 'function'),
    ),
    'a class': Program(
        a_program("""
            if (1) { class C {} }
            console.log(typeof C);
            """),
        prints('undefined'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestATakenBranchKeepsWhatItsBlockScopes(TestBase):

    def test_a_taken_branch_answers_what_it_answered(self):
        rows = A_DECLARATION_A_TAKEN_BRANCH_HOLDS
        self.assertEqual(_still_answered(rows), _as_it_answers_them(rows))


class TestTheBlockATakenBranchScopesIsKept(TestBase):
    """
    A function declaration that is the whole of an `if` clause is read as if it stood in a block of
    its own (Annex B.3.4), so the clause form comes back with a block as well.
    """

    _IN_A_FUNCTION = ('a block function', 'a function that is the whole of the clause')

    _BLOCK_KEPT_IN_THE_FUNCTION = inspect.cleandoc(
        """
        function outer() {
          console.log(typeof W);
          {
            function W() {
              return 1;
            }
          }
          console.log(typeof W);
        }
        outer();
        """
    )

    _FOLDED_IN_A_FUNCTION = inspect.cleandoc(
        """
        console.log('undefined');
        console.log('function');
        """
    )

    @backlog
    def test_each_taken_branch_in_a_function_keeps_its_block_there_or_is_folded_to_what_it_prints(self):
        for label in self._IN_A_FUNCTION:
            with self.subTest(label=label):
                self.assertIn(
                    folded(A_DECLARATION_A_TAKEN_BRANCH_HOLDS[label].text),
                    (self._BLOCK_KEPT_IN_THE_FUNCTION, self._FOLDED_IN_A_FUNCTION),
                )

    @opportunity
    def test_each_taken_branch_in_a_function_is_folded_to_what_it_prints(self):
        self.assertEqual(
            {label: folded(A_DECLARATION_A_TAKEN_BRANCH_HOLDS[label].text) for label in self._IN_A_FUNCTION},
            dict.fromkeys(self._IN_A_FUNCTION, self._FOLDED_IN_A_FUNCTION),
        )

    def test_a_class_in_a_taken_branch_keeps_its_block_or_is_removed(self):
        self.assertIn(
            folded(A_DECLARATION_A_TAKEN_BRANCH_HOLDS['a class'].text),
            (
                inspect.cleandoc(
                    """
                    {
                      class C {}
                    }
                    console.log(typeof C);
                    """
                ),
                'console.log(typeof C);',
            ),
        )

    @opportunity
    def test_an_unused_class_in_a_taken_branch_is_removed(self):
        self.assertEqual(folded(A_DECLARATION_A_TAKEN_BRANCH_HOLDS['a class'].text), 'console.log(typeof C);')


A_CALL_TO_A_NAME_THE_CALL_WROTE_AT_ENTRY = {
    'a read after the call': Program(
        a_program("""
            function outer(a = 0) {
              var x = 1;
              var a = function () { x = 2; };
              a();
              console.log(x);
            }
            outer();
            """),
        prints('2'),
    ),
    'a read from another function': Program(
        a_program("""
            function outer(a = 0) {
              var x = 1;
              var a = function () { x = 2; };
              a();
              function reader() { console.log(x); }
              reader();
            }
            outer();
            """),
        prints('2'),
    ),
    'a mapped arguments a default stands beside': Program(
        a_program("""
            var c = { k: 1 };
            function g(o, z = 1) { arguments[0].k = 99; }
            g(c);
            console.log(c.k);
            """),
        prints('99'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAParameterScopeDoesNotHideWhatACallDoes(TestBase):

    def test_a_call_the_parameter_scope_splits_still_writes(self):
        rows = A_CALL_TO_A_NAME_THE_CALL_WROTE_AT_ENTRY
        self.assertEqual(_still_answered(rows), _as_it_answers_them(rows))


class TestAFoldPastACallTheParameterScopeSplitsReadsWhatTheCallWrote(TestBase):

    _FOLDED_TO_WHAT_EACH_PRINTS = {
        'a read after the call': 'console.log(2);',
        'a read from another function': 'console.log(2);',
        'a mapped arguments a default stands beside': 'console.log(99);',
    }

    def test_each_program_comes_back_as_it_was_written_or_folded_to_what_it_prints(self):
        for label, row in A_CALL_TO_A_NAME_THE_CALL_WROTE_AT_ENTRY.items():
            with self.subTest(label=label):
                self.assertIn(folded(row.text), (printed(row.text), self._FOLDED_TO_WHAT_EACH_PRINTS[label]))

    @opportunity
    def test_each_program_is_folded_to_what_it_prints(self):
        rows = A_CALL_TO_A_NAME_THE_CALL_WROTE_AT_ENTRY
        self.assertEqual(
            {label: folded(row.text) for label, row in rows.items()},
            self._FOLDED_TO_WHAT_EACH_PRINTS,
        )


AN_EXPORTED_DECLARATION_THE_FILE_ALSO_NAMES = Program(
    a_program("""
        export function atob(s) { return 'mine:' + s; }
        console.log(atob('AAAA'));
        """),
    prints('mine:AAAA'),
    Reading.ES_MODULE,
)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnExportedDeclarationIsStillADeclaration(TestBase):

    def test_an_exported_declaration_answers_the_call_the_file_makes(self):
        self.assertEqual(
            AN_EXPORTED_DECLARATION_THE_FILE_ALSO_NAMES.read(),
            AN_EXPORTED_DECLARATION_THE_FILE_ALSO_NAMES.required(),
        )


class TestTheCallAnExportedDeclarationAnswersIsFoldedFromIt(TestBase):

    def test_the_call_is_folded_from_the_exported_function(self):
        self.assertEqual(
            folded(AN_EXPORTED_DECLARATION_THE_FILE_ALSO_NAMES.text),
            inspect.cleandoc(
                """
                export function atob(s) {
                  return 'mine:' + s;
                }
                console.log('mine:AAAA');
                """
            ),
        )


A_GLOBAL_PROPERTY_NAMED_THROUGH_A_REALM = {
    'a write in another realm and a read in this one': (
        a_program("""
            top.foo = 1;
            console.log(globalThis.foo);
            """),
        "top.foo = 1;\nconsole.log(globalThis.foo);",
    ),
    'a write in this realm and a read in another': (
        a_program("""
            globalThis.qux = 1;
            console.log(top.qux);
            """),
        "globalThis.qux = 1;\nconsole.log(top.qux);",
    ),
    'a write and a read in this realm': (
        a_program("""
            globalThis.bar = 1;
            console.log(globalThis.bar);
            """),
        "globalThis.bar = 1;\nconsole.log(bar);",
    ),
}


class TestARealmDecidesWhetherAnAliasCollapses(TestBase):

    def test_only_a_same_realm_alias_collapses(self):
        self.assertEqual(
            {
                label: folded(source)
                for label, (source, _) in A_GLOBAL_PROPERTY_NAMED_THROUGH_A_REALM.items()
            },
            {
                label: text
                for label, (_, text) in A_GLOBAL_PROPERTY_NAMED_THROUGH_A_REALM.items()
            },
        )
