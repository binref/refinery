"""
Which scope holds a name, for the three shapes `refinery.lib.scripts.js.analysis.model` builds
wrongly: the parameter list of a function that carries an expression, the block a function is
declared in, and the top level of a classic script, whose `this` is the global object.

The defects themselves are entries of `test.lib.scripts.js.test_release_blockers`. What is here is
the other half of each of them, which a fix is answerable for just as much: the programs the model
already answers correctly and must go on answering, and the reductions a correct answer costs. A
scope that is split apart, a value that stops being folded, and a declaration that stops being
removed each buy correctness with recall, and a cost written down before the change is the only one
a reader can tell from a regression afterwards.

The receiver table is the third kind: it is a question about JavaScript rather than about this
project, asked of a classic script because that is the execution model the question exists in at
all. A decorator is the one position it does not name, because no engine here parses one - Node
answers a `SyntaxError` for the class this file's parser reads - so there is nothing to write
down.

SECURITY: every program here is hand-authored in this file and benign. No sample and no stored
obfuscator fixture may be fed to this.
"""
from __future__ import annotations

import inspect
import unittest

from test import TestBase
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


#: A program declaring a function inside a block that the model already answers correctly, mapped to
#: the behavior an engine gives it. Where the copy Annex B makes reaches the enclosing scope, the
#: name holds the function from the declaration onwards, and every one of the conditions that
#: suppresses the copy leaves the enclosing name holding what it held.
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
    """
    The half of the block-function family the model answers correctly today. Every condition B.3.3.1
    lists for suppressing the copy is here, because a fix that models the copy has to model each of
    them, and a fix that suppresses one too many is not visible in the entries the defect is pinned
    by: those are all programs the copy is wrong about, and suppressing every copy would answer all
    of them.
    """

    def test_a_block_function_the_program_answers_for_is_answered_the_same_way(self):
        rows = A_BLOCK_FUNCTION_THE_PROGRAM_STILL_ANSWERS_FOR
        self.assertEqual(_still_answered(rows), _as_it_answers_them(rows))


#: A program whose parameter default reads a name its own body declares again, mapped to the
#: behavior an engine gives it. Every kind of function a default may be written on is here, because
#: the scope a default evaluates in is a property of having one at all and of nothing else.
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
    """
    Retired from `test.lib.scripts.js.test_release_blockers` and kept as the regression it retired.

    A function whose parameters carry an expression evaluates them in a parameter scope of its own
    whose parent is the scope enclosing the function, so a default never reads what the body
    declares: the body's declarations do not exist yet when a default runs. The scope model used to
    give a function one scope for parameters and body together, so a default's read resolved to the
    body's binding, and the folds downstream substituted the body's value into the default or
    deleted the very declaration the default read.

    The misattribution cost the outer binding as much as it cost the default: a reference the body's
    binding was credited with was one the outer binding never recorded, so a pass counting what
    reads the outer binding counted one too few. `a wrapper a default names` is that half, and
    `A_WRAPPER_A_DEFAULT_AND_A_BODY_BOTH_NAME` beside it is the positive companion:
    `refinery.lib.scripts.js.deobfuscation.argwrap` used to refuse a wrapper a default of its own
    body named and had no way to see the other one at all, and now expands both.
    """

    def test_a_parameter_default_reads_the_scope_around_the_function(self):
        rows = A_PARAMETER_DEFAULT_READING_PAST_THE_BODY
        self.assertEqual(_still_answered(rows), _as_it_answers_them(rows))


#: A program whose self-disabling wrapper is called from a parameter default, mapped to the behavior
#: an engine gives it and to the text the deobfuscation answers with. Both are the positive
#: companion of `A_PARAMETER_DEFAULT_READING_PAST_THE_BODY`: a call in a default is a call like any
#: other once the default is in a scope of its own, so the expansion reaches it.
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
    """
    A call in a parameter default reaches the wrapper its name denotes, so the expansion is
    equivalent for it exactly as it is for a call in a body. The pass used to refuse every wrapper
    whose declaration stood in a body with parameters, because a reference in a default was recorded
    against the body's binding and it had no way to tell that reference from a real one.
    """

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


#: A program whose body declares a `var` of a parameter's name, mapped to the exact text the
#: deobfuscation answers with. The read after the declarator is one the value reaches, and the
#: parameter scope gives it up: the name is written twice, once by the call and once by the
#: declarator, and the second write is the only one anything in the text says a value for.
A_FOLD_THE_ENTRY_COPY_GIVES_UP = a_program("""
    function f(x = 1) { console.log(x); var x = 5; console.log(x); }
    f();
    """)


class TestAFoldTheEntryCopyGivesUpIsGivenUp(TestBase):
    """
    What the parameter scope costs, written down where it is paid. A body `var` of a parameter's
    name is a binding the call writes before any statement runs, holding the argument, and the
    declarator that follows is a second write. Two writes are not one value, so the name denotes
    nothing the whole body over and the read after the declarator stops being answered - where the
    one binding the two used to share was declined for counting two declarations, and the read
    before the declarator was answered by ordering alone.

    Read from the text and from nothing else: the program prints `1` and then `5` either way.
    """

    def test_the_read_after_the_declarator_is_no_longer_folded(self):
        self.assertEqual(
            folded(A_FOLD_THE_ENTRY_COPY_GIVES_UP),
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
        )


#: A classic script reading one of its own top-level declarations through the `this` its top level
#: holds, or writing a global property through it, mapped to the behavior a host gives it.
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
    """
    Retired from `test.lib.scripts.js.test_release_blockers` and kept as the regression it retired.

    At the top level of a classic script `this` is the global object, and a top-level `var` or
    function declaration is a property of that object, so `this.q` is a read of `q` and nothing
    else. `refinery.lib.scripts.js.analysis.model` used to recognize an access through `globalThis`,
    `global`, `window`, `self`, `top` and `frames` as reaching such a binding and record the member
    access in its place, with `this` not among them, so a read written that way was recorded nowhere
    and the binding read as one nothing outside its declaration named.

    Every pass that removes a declaration on that answer then removed it, and the last row is the
    same gap costing a value rather than a declaration: a computed write the model did not see was
    one the folds behind it read past, so a program that printed what the write put there came back
    printing what the declaration did. What makes `this` different from the six names is that it is
    the global object only where it is written, and a function body may hold any receiver at all,
    which is why it is read from the position it stands in rather than from a set of names.
    """

    def test_a_declaration_a_top_level_this_reads_is_still_read(self):
        rows = A_TOP_LEVEL_THIS_REACHING_THE_GLOBAL_OBJECT
        self.assertEqual(_still_answered(rows), _as_it_answers_them(rows))


class TestTheDeclarationATopLevelThisReadsIsKept(TestBase):
    """
    The same law read from the text and from nothing else, so that it is not answered only where
    Node.js is installed: what a `this` at the top level names is left standing, and the read
    naming it is left standing beside it.
    """

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


#: A program declaring a function inside a block, mapped to the behavior an engine gives it. The
#: block is where the name lives in strict code and the copy Annex B makes is what puts it outside
#: one in sloppy code, so the shapes here differ in the mode the block is read under and in where
#: the name is read from.
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
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFunctionDeclaredInsideABlockIsDeclaredInsideIt(TestBase):
    """
    Retired from `test.lib.scripts.js.test_release_blockers` and kept as the regression it retired.

    A function declared inside a plain block is a lexical binding of that block, and what reaches
    the enclosing variable scope is decided by the mode. Strict code puts nothing there: a call
    beside the block reads no binding and throws. Sloppy code creates a `var` of the name at the
    entry of the enclosing function and copies the block's function into it where the declaration
    runs, so a call before the block reads `undefined` and throws too, and only a call after it
    answers the function.
    """

    def test_a_block_function_is_read_from_where_the_language_binds_it(self):
        rows = A_FUNCTION_DECLARED_INSIDE_A_BLOCK
        self.assertEqual(_still_answered(rows), _as_it_answers_them(rows))


#: A program whose block is one no branch of it takes, mapped to the behavior an engine gives it.
#: What a dead block declares is declared all the same - a `var` and, in sloppy code, the `var` half
#: of a function declaration are created at the entry of the enclosing scope, before any branch is
#: decided - so a read of the name answers `undefined` rather than throwing.
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
    """
    Retired from `test.lib.scripts.js.test_release_blockers` and kept as the regression it retired.

    Removing a branch no condition takes removes the statements it ran, and a declaration is not
    only a statement: a `var` and the `var` half of a sloppy function declaration name something
    from the entry of the enclosing scope onwards, whether or not the branch holding them is ever
    reached. `refinery.lib.scripts.js.deobfuscation.deadcode` used to drop the branch whole, so the
    name the program answered `undefined` for was left bound to nothing and reading it threw.

    The two halves are one defect and are kept as two rows because one rule reads both shapes, and
    the same rule decides the other direction too: a *taken* branch is unwrapped into the list
    around it, which may only happen where the block scopes nothing, so the block a strict function
    is declared in is kept exactly as a block holding a `let` is.
    """

    def test_a_declaration_a_dead_block_holds_is_still_read(self):
        rows = A_DECLARATION_A_DEAD_BLOCK_HOLDS
        self.assertEqual(_still_answered(rows), _as_it_answers_them(rows))


class TestTheDeclarationsADeadBlockHeldAreKept(TestBase):
    """
    The same law read from the text and from nothing else, so that it is not answered only where
    Node.js is installed: what comes back is the read, with a `var` of the name left standing in
    front of it and the statements the branch would have run gone.
    """

    def test_each_dead_block_leaves_the_names_it_declared(self):
        self.assertEqual(
            {
                label: folded(row.text)
                for label, row in A_DECLARATION_A_DEAD_BLOCK_HOLDS.items()
            },
            {
                'a function no branch declares': 'var W;\nconsole.log(W);',
                'a var no branch declares': 'var v;\nconsole.log(v);',
                'a function that is the whole of an if clause': inspect.cleandoc(
                    """
                    function outer() {
                      var W;
                      console.log(W);
                    }
                    outer();
                    """
                ),
            },
        )


#: A program whose block function writes a name declared outside the block, mapped to the behavior
#: an engine gives it. The call is the only thing that writes the name, so a reader that cannot say
#: which function a call reaches has to say that any of them may have written it.
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
    """
    The control that says which direction a refusal is safe in. `SemanticModel.singular_value` is
    read as a value, where declining to answer costs a fold and nothing else, and it is read through
    `EffectModel.function_of` to decide which functions a call may have run, where declining to
    answer is what a caller must not treat as `no function ran`.

    Both programs here write a name from inside a block-declared function and read it afterwards.
    Refusing to value the callee and leaving the two readers as they are turns each of them into a
    program printing `1`: the write inside the body is deleted, the declaration it wrote to is
    removed, and the read is folded to what the initializer held. So this is not a recall cost to be
    weighed but the thing that makes the refusal a wrong answer, and it belongs beside the refusal
    rather than after it.
    """

    def test_a_write_from_a_block_function_still_reaches_the_name_outside(self):
        rows = A_CALL_TO_A_BLOCK_FUNCTION_THAT_WRITES_PAST_ITS_BLOCK
        self.assertEqual(_still_answered(rows), _as_it_answers_them(rows))


#: A call to a block-declared function, mapped to the exact text the deobfuscation answers with. A
#: call the copy has run before is answered from the declaration; one written before the copy runs
#: is not, since the name holds `undefined` there.
A_CALL_TO_A_BLOCK_FUNCTION = {
    'a call after the block': (
        a_program("""
            function outer() {
              { function W() { return 1; } }
              console.log(W());
            }
            outer();
            """),
        inspect.cleandoc(
            """
            function outer() {
              {}
              console.log(1);
            }
            outer();
            """
        ),
    ),
    'a call inside the block': (
        a_program("""
            function outer() {
              { function W() { return 1; } console.log(W()); }
            }
            outer();
            """),
        inspect.cleandoc(
            """
            function outer() {
              {
                console.log(1);
              }
            }
            outer();
            """
        ),
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
        inspect.cleandoc(
            """
            function outer() {
              {}
              console.log(1);
            }
            outer();
            """
        ),
    ),
    'a call before the block': (
        a_program("""
            function outer() {
              try { console.log(W()); } catch (e) { console.log('threw'); }
              { function W() { return 1; } }
            }
            outer();
            """),
        inspect.cleandoc(
            """
            function outer() {
              try {
                console.log(W());
              } catch (e) {
                console.log('threw');
              }
              {
                function W() {
                  return 1;
                }
              }
            }
            outer();
            """
        ),
    ),
}


class TestACallToABlockFunctionIsFoldedWhereTheCopyHasRun(TestBase):
    """
    What the block-function fix costs, which is nothing but the answers that were wrong. A name
    Annex B copies into the enclosing scope holds the function from the point the declaration runs,
    so a call written after it is answered from the declaration exactly as it was, and one written
    before it is not answered at all - where it used to be answered with the function, which is the
    entry this retired.

    Read from the text and from nothing else: the first three programs print `1` either way, and
    only the last one prints differently, which the entry it retired says.
    """

    def test_each_call_is_folded_where_the_copy_has_run(self):
        self.assertEqual(
            {
                label: folded(program)
                for label, (program, _) in A_CALL_TO_A_BLOCK_FUNCTION.items()
            },
            {label: text for label, (_, text) in A_CALL_TO_A_BLOCK_FUNCTION.items()},
        )


#: A program whose parameters and body answer for the same name and which the model already answers
#: correctly, mapped to the behavior an engine gives it. A parameter and a body `var` of one name
#: are one binding the argument initializes, and the name of a named function expression is a
#: binding of its own, outside the parameters and behind any of them that spells it.
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
    """
    The half of the parameter-default family the model answers correctly today. Splitting the
    parameters of a function into a scope of their own is what the defect needs, and every one of
    these programs is answered by the two being one scope, so each of them is a way for the split to
    go too far: a body `var` that stops seeing the argument, a lexical binding that stops being
    reachable, or the name of a function expression put on the wrong side of the parameters.
    """

    def test_a_parameter_scope_the_program_answers_for_is_answered_the_same_way(self):
        rows = A_PARAMETER_SCOPE_THE_PROGRAM_STILL_ANSWERS_FOR
        self.assertEqual(_still_answered(rows), _as_it_answers_them(rows))


#: A position of a classic script, mapped to the behavior a host gives a program that reports from
#: it whether its `this` is the global object. This is the table a fix has to agree with: the
#: positions answering `true` are exactly the ones a top-level declaration is reachable from through
#: `this`, and the ones answering `false` are the ones where `this` is whatever a caller passed.
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
    """
    Where the `this` of a classic script is its global object. The boundary is the one
    `SemanticModel.walk_receiver_scope` already draws for a different purpose: an arrow carries the
    `this` of what encloses it, and the head of a class - its `extends` clause and its computed keys
    - is evaluated where the class is written, while a method, a getter, a field initializer and a
    static block each take one of their own.

    The last two rows are the pair that says the boundary is not the whole rule: a call written with
    no receiver hands the body `undefined`, and only sloppy code replaces that with the global
    object, so a body reached that way is the global object under one mode and not under the other.
    """

    def test_each_position_reports_the_receiver_it_holds(self):
        rows = THE_RECEIVER_A_POSITION_OF_A_SCRIPT_HOLDS
        self.assertEqual(_still_answered(rows), _as_it_answers_them(rows))


#: A classic script whose top level writes a global property under a key no reading of the text
#: gives, mapped to the exact text the deobfuscation answers with today. The write may put anything
#: anywhere on the global object, so a model that reads it has to stop removing what the file does
#: not name - and `z` here is exactly that.
A_REMOVAL_A_COMPUTED_WRITE_THROUGH_THIS_STANDS_BESIDE = a_program("""
    var z = 1;
    var k = 'q';
    this[k] = 2;
    console.log(3);
    """)


#: The same script with nothing written through `this` at all, which is the control: a top-level
#: declaration no reading of the file reaches is removed today and has to go on being removed, or
#: the fix has bought the entry it is for by keeping every declaration of every script.
A_TOP_LEVEL_DECLARATION_NOTHING_IN_THE_FILE_NAMES = a_program("""
    var q = function (a) { console.log(a); };
    console.log(1);
    """)


class TestARemovalTheGlobalObjectFixGivesUp(TestBase):
    """
    What the top-level `this` fix costs. Reading `this` as the global object means reading a write
    through it as a write of a global property, and a write under a computed key is a write of a
    property no reading of the text names, so every removal in the file it stands in stops - the
    declaration of `z`, which nothing reads, and the fold of `k`, which the write reads. The control
    beside it is the file with no such write, whose removals go on happening.

    Read from the text and from nothing else: both programs print what they printed either way.
    """

    def test_a_removal_a_computed_write_stands_beside_no_longer_happens(self):
        self.assertEqual(
            folded(A_REMOVAL_A_COMPUTED_WRITE_THROUGH_THIS_STANDS_BESIDE),
            inspect.cleandoc(
                """
                var z = 1;
                var k = 'q';
                this[k] = 2;
                console.log(3);
                """
            ),
        )

    def test_a_top_level_declaration_nothing_names_is_still_removed(self):
        self.assertEqual(
            folded(A_TOP_LEVEL_DECLARATION_NOTHING_IN_THE_FILE_NAMES),
            'console.log(1);',
        )


#: A program whose taken branch holds a declaration the block it stands in is the scope of, mapped
#: to the behavior an engine gives it. What the block scopes is not only a `let`: a class is scoped
#: to it, and so is a function declaration, whose name outside the block holds it from the point the
#: declaration runs rather than from the entry of the scope.
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
    """
    The other direction of `TestADeclarationADeadBlockHoldsIsStillDeclared`. A taken branch is
    unwrapped into the list around it, which may only happen where the block scopes nothing:
    `refinery.lib.scripts.js.deobfuscation.deadcode` kept the block for a `let`, a `const` and a
    strictly bound function, and lifted a class out of the scope it belonged to and a sloppily
    declared function to the entry of the enclosing one, where the program held `undefined` until
    the declaration ran.

    The clause form is the same defect written without a block, which §B.3.4 reads as the block it
    would have had, so it is answered with one.
    """

    def test_a_taken_branch_answers_what_it_answered(self):
        rows = A_DECLARATION_A_TAKEN_BRANCH_HOLDS
        self.assertEqual(_still_answered(rows), _as_it_answers_them(rows))


class TestTheBlockATakenBranchScopesIsKept(TestBase):
    """
    The same law read from the text and from nothing else: the `if` is gone and the block the
    declaration was scoped to is still standing around it.
    """

    def test_each_taken_branch_keeps_its_block(self):
        self.assertEqual(
            {
                label: folded(row.text)
                for label, row in A_DECLARATION_A_TAKEN_BRANCH_HOLDS.items()
            },
            {
                'a block function': inspect.cleandoc(
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
                ),
                'a function that is the whole of the clause': inspect.cleandoc(
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
                ),
                'a class': inspect.cleandoc(
                    """
                    {
                      class C {}
                    }
                    console.log(typeof C);
                    """
                ),
            },
        )


#: A program calling a function through a body `var` repeating a parameter's name, mapped to the
#: behavior an engine gives it. The call writes that name before any statement runs, so nothing in
#: the text says what it holds - and a reader that cannot say which function such a call reaches has
#: to say that any function of the file may have written what the call wrote.
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
    """
    What the parameter scope must not cost. The first two rows are the entry copy read as a callee:
    the name is written by the call and by the declarator both, so no value is stated for it, while
    every invocation of the function still goes through that one name - so a reader asking whether
    the function escapes answers no and a reader asking which function a call reaches answers
    nothing, and a caller conjoining the two concluded that the call wrote nothing.

    The third row is the same split read from the other side: a function whose parameter list holds
    an expression binds its `arguments` object in the parameter scope, and a reader taking it out of
    the body's scope alone found none, so a container the function writes through `arguments` was
    read as one nothing writes.
    """

    def test_a_call_the_parameter_scope_splits_still_writes(self):
        rows = A_CALL_TO_A_NAME_THE_CALL_WROTE_AT_ENTRY
        self.assertEqual(_still_answered(rows), _as_it_answers_them(rows))


class TestNothingIsFoldedPastACallTheParameterScopeSplits(TestBase):
    """
    The same law read from the text and from nothing else: every one of these programs comes back
    as it was written, since the value each of them reads is one no reading of the text states.
    """

    def test_each_program_comes_back_as_it_was_written(self):
        rows = A_CALL_TO_A_NAME_THE_CALL_WROTE_AT_ENTRY
        self.assertEqual(
            {label: folded(row.text) for label, row in rows.items()},
            {label: printed(row.text) for label, row in rows.items()},
        )


#: A module exporting a declaration the file also names, mapped to the behavior an engine gives it.
#: An `export` names what the declaration under it declares and declares nothing of its own.
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
    """
    A declaration written under an `export` binds its name exactly as one written without it. The
    scope model reads a statement list one statement at a time and an export is a statement holding
    a declaration rather than being one, so a reader not looking through it finds no binding at all
    - and a name nothing in the file binds is a free name, which for `atob` is the host's.
    """

    def test_an_exported_declaration_answers_the_call_the_file_makes(self):
        self.assertEqual(
            AN_EXPORTED_DECLARATION_THE_FILE_ALSO_NAMES.read(),
            AN_EXPORTED_DECLARATION_THE_FILE_ALSO_NAMES.required(),
        )


class TestTheCallAnExportedDeclarationAnswersIsFoldedFromIt(TestBase):
    """
    The same law read from the text and from nothing else: the call is answered with what the
    exported function returns and not with what the host's function of that name returns.
    """

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


#: An access on a spelling of the global object, mapped to the exact text the deobfuscation answers
#: with. `top` and `frames` name the global object of another document, so a property one of them
#: carries is not a property of this file's realm and a read of the bare name does not find it.
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
    """
    `refinery.lib.scripts.js.analysis.model.SAME_REALM_GLOBAL_OBJECT_ALIASES` is the set a
    rewrite keys on and the wider one in `refinery.lib.scripts.js.analysis.model` is what a reading
    of code's reach keys on. `refinery.lib.scripts.js.deobfuscation.simplify` read the wider one, so
    a property written on another document's global object was collapsed to a bare name of this one
    and the `undefined` a read answered became a `ReferenceError`.

    The third row is the control: within one realm the collapse is what the pass is for.
    """

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
