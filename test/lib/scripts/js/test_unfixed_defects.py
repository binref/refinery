"""
A ledger of JavaScript defects that are known and not yet fixed.

Each entry asserts what a correct implementation does, never what the code does today, and carries a
marker for how much its defect matters: `test.blocker`, `test.todo` or `test.backlog` where the
deobfuscation behaves otherwise than its input, and `test.opportunity` where it behaves the same and
is only less simplified. An entry leaves this file when its defect is fixed, together with its
marker. Tests without a marker are guards and engine checks that pass.

An entry marked `wontfix` is a defect that only a shape made up for it reaches. It never runs, its
marker says why no real input has the shape, and nobody is to fix it or bend a design around it.

Rows that belong to a corpus a law elsewhere is stated over stay in that corpus and are imported
here; they rejoin the law when the marker comes off.

An entry whose programs have roots a fix may reach separately is pinned by one test per program, so
that a fix reaching only some of them is reported as a fix. The decorator that installs these tests
is

    one_expected_failure_per_program
"""
from __future__ import annotations

import inspect
import unittest

from test import TestBase, backlog, opportunity, todo
from test.lib.scripts.js.analysis.differential import (
    JsEvaluation,
    behavior,
    completion_values,
    deobfuscate_source,
    module_graph_behavior,
    node_executable,
)
from test.lib.scripts.js.deobfuscation.test_array_length_reads import (
    A_COUNT_THE_FOLD_DOES_NOT_REACH,
)
from test.lib.scripts.js.deobfuscation.test_a_table_read_through_an_accessor import (
    deobfuscated_by_the_unit,
    with_words,
)
from test.lib.scripts.js.deobfuscation.test_b91strings import (
    DEFAULTED_HEAD,
    HEAD,
    OTHER_TABLE,
    SLICED,
    SWAPPED,
    TABLE,
    accessor,
    decoder,
    decoder_body,
    defaulted,
    slicing,
)
from test.lib.scripts.js.deobfuscation.test_call_answers_a_wrapper import (
    a_string_array_whose_rotation_runs,
)
from test.lib.scripts.js.deobfuscation.test_selfchecks import (
    DOUBLE,
    DOUBLE_42,
    NEW_HELPERS,
    SET_A_LINE_BREAK,
    checked,
    NAME_OF,
    NAME_OF_5,
    checked_by_name,
    guarded,
)
from test.lib.scripts.js.deobfuscation import test_the_file_kind as the_file_kind
from test.lib.scripts.js.ledger import (
    Program,
    Reading,
    a_program,
    a_walk_of,
    an_accessor_at,
    as_classic_scripts,
    before_and_after,
    before_and_after_in_a_host,
    each_program_still_prints,
    evaluated_in_a_body,
    folded,
    on_separate_lines,
    one_expected_failure_per_program,
    printed,
    prints,
    well_formed,
    wontfix,
)
from test.lib.scripts.js.test_parameter_grammar import (
    A_FUNCTION_EXPRESSION_NAME_ONLY_THE_ENCLOSING_KIND_RESERVES,
)
from test.lib.scripts.js.test_parser_recovery import (
    A_POSITION_NAMING_A_BINDING_THE_FILE_CREATES,
    A_WORD_NO_MODULE_MAY_BIND,
    unread_spans,
)

from refinery.lib.scripts.js.analysis.cache import ModelCache
from refinery.lib.scripts.js.analysis.environment import HostEnvironment
from refinery.lib.scripts.js.model import static_string
from refinery.lib.scripts.js.options import ExecutionModel
from refinery.lib.scripts.js.parser import JsParser
from refinery.units.scripting.djs import djs


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnExpressionNamedByAWordOnlyTheEnclosingKindReservesIsAProgram(TestBase):
    """
    A function expression's own name is reserved only by the kind of that expression and not by the
    kind of the function around it, so a plain function expression named `yield` inside a generator,
    or one named `await` inside an async function, is a program.
    """

    def test_printing_one_of_them_gives_a_program_that_runs_the_same_way(self):
        rows = A_FUNCTION_EXPRESSION_NAME_ONLY_THE_ENCLOSING_KIND_RESERVES
        self.assertEqual(
            {source: behavior(printed(source)) for source in rows},
            {source: ('', None) for source in rows},
        )

    def test_the_deobfuscation_of_one_that_prints_keeps_what_it_prints(self):
        source = (
            'function* g() { var f = function yield() { return 1; };'
            ' console.log(typeof f); } g().next();'
        )
        self.assertEqual(before_and_after(source), (('function\n', None), ('function\n', None)))


class TestABindingNamedByAWordNoModuleMayBindIsNoProgram(TestBase):

    @wontfix(
        'no engine loads a module whose import binds a word the language reserves, and no obfuscator '
        'or program writes one'
    )
    def test_a_binding_named_by_a_word_no_module_may_bind_is_not_a_well_formed_program(self):
        sources = [
            template.format(name=word)
            for template in A_POSITION_NAMING_A_BINDING_THE_FILE_CREATES.values()
            for word in A_WORD_NO_MODULE_MAY_BIND
        ]
        self.assertEqual(
            {source: well_formed(source) for source in sources},
            {source: False for source in sources},
        )


class TestAModulesTopLevelAwaitIsAProgram(TestBase):

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_a_module_awaiting_at_its_top_level_still_behaves_so(self):
        source = 'export {}; await 1; console.log(2);'
        self.assertEqual(before_and_after(source, module=True), (prints('2'), prints('2')))

    @backlog
    def test_a_top_level_await_beside_module_syntax_is_a_well_formed_program(self):
        self.assertEqual(well_formed('export {}; await 1;'), True)


#: A `using` declaration (ECMAScript 2026) runs the disposer of its value when the block holding it
#: is left, so each program prints `2` and then `1` under a Node that knows the declaration; Node 22
#: refuses each of them. A script may not spell one at its top level.
A_USING_DECLARATION_IN_EACH_PLACE_A_SCRIPT_ALLOWS = {
    'a block': '{ using x = { [Symbol.dispose]() { console.log(1); } }; console.log(2); }',
    'a function body': (
        'function f() { using x = { [Symbol.dispose]() { console.log(1); } }; console.log(2); }'
        ' f();'
    ),
    'an async function body': (
        'async function f() {'
        ' await using x = { [Symbol.asyncDispose]() { console.log(1); } }; console.log(2); }'
        ' f();'
    ),
    'a for-of head': 'for (using x of [{ [Symbol.dispose]() { console.log(1); } }]) console.log(2);',
}


class TestAUsingDeclarationIsAProgram(TestBase):

    @backlog
    def test_a_using_declaration_is_a_well_formed_program(self):
        rows = A_USING_DECLARATION_IN_EACH_PLACE_A_SCRIPT_ALLOWS
        self.assertEqual(
            {name: well_formed(source) for name, source in rows.items()},
            {name: True for name in rows},
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_the_deobfuscation_of_a_using_declaration_behaves_as_the_declaration_does(self):
        pairs = {
            name: before_and_after(source)
            for name, source in A_USING_DECLARATION_IN_EACH_PLACE_A_SCRIPT_ALLOWS.items()
        }
        self.assertEqual(
            {name: after for name, (_, after) in pairs.items()},
            {name: before for name, (before, _) in pairs.items()},
        )


class TestASourcePhaseImportIsAProgram(TestBase):
    """
    `import source x from 'm'` is a source phase import (ECMAScript 2026), which binds `x` to the
    source of the module `m` rather than to its namespace.
    """

    @backlog
    def test_a_source_phase_import_prints_back_as_written(self):
        source = "import source x from 'm';"
        self.assertEqual((well_formed(source), printed(source)), (True, source))


class TestALiteralNoElementOfWhichRunsIsCounted(TestBase):

    @opportunity
    def test_a_literal_whose_elements_are_not_written_as_literals_is_counted(self):
        counts = A_COUNT_THE_FOLD_DOES_NOT_REACH
        self.assertEqual(
            [folded(F'console.log({read});') for read in counts],
            [F'console.log({count});' for count in counts.values()],
        )


A_STRICT_BODY_ASSIGNING_TO_AN_UNDECLARED_NAME = {
    (
        "function f() { 'use strict'; try { und = 1; return 'ok'; }"
        " catch (e) { return 'threw'; } }\n"
        'console.log(f());\n'
    ): ('threw\n', None),
    "(function () { 'use strict'; und = 1; console.log(1); })();\n": ('', 'ReferenceError'),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestTheEvaluatorRunsABodyInTheModeItDeclares(TestBase):

    @backlog
    def test_an_assignment_to_an_undeclared_name_throws_in_a_strict_body(self):
        rows = A_STRICT_BODY_ASSIGNING_TO_AN_UNDECLARED_NAME
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            {source: (answer, answer) for source, answer in rows.items()},
        )


#: A class body is strict code, so the row with a class static block assigns in strict code although
#: it holds no directive.
A_STRICT_REGION_ASSIGNING_TO_NO_BINDING = {
    "function f(b) { 'use strict'; var q = b + 1; undeclared_a = 1; return q; }"
    ' console.log(f(2));': ('', 'ReferenceError'),
    "'use strict'; undeclared_b = 1; console.log(3);": ('', 'ReferenceError'),
    'var out = 3; class C { static { undeclared_c = 1; } } console.log(out);':
        ('', 'ReferenceError'),
    "'use strict'; function f() { undeclared_d = 1; } f(); console.log(4);":
        ('', 'ReferenceError'),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAWriteOnlyStrictCodeRefusesIsNotADeadStore(TestBase):

    @backlog
    def test_an_assignment_to_no_binding_throws_where_the_region_is_strict(self):
        rows = A_STRICT_REGION_ASSIGNING_TO_NO_BINDING
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            {source: (answer, answer) for source, answer in rows.items()},
        )


A_STORE_INTO_A_WRAPPER_NAME_AN_ES_MODULE_LEAVES_UNBOUND = {
    'a store to exports nothing reads': Program(
        a_program("""
            try { exports = 1; } catch (e) { console.log(e.name); }
            console.log('end');
            """),
        prints('ReferenceError', 'end'),
        Reading.ES_MODULE,
    ),
}

#: In sloppy code a function declared in a block also creates a `var` in the function around the
#: block. An ES module is strict and creates none, so the store reaches the outer `g` and the
#: program prints `inner`.
A_STORE_INTO_A_NAME_AN_ES_MODULE_LEAVES_UNBOUND = {
    'a store to the var of a block function nothing reads': Program(
        a_program("""
            var g = 'outer';
            function h() {
              { function g() {} }
              g = 'inner';
            }
            h();
            console.log(g);
            """),
        prints('inner'),
        Reading.ES_MODULE,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_STORE_INTO_A_NAME_AN_ES_MODULE_LEAVES_UNBOUND, backlog)
class TestAStoreIntoANameAnEsModuleLeavesUnboundIsNotADeadStore(TestBase):
    pass


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(
    A_STORE_INTO_A_WRAPPER_NAME_AN_ES_MODULE_LEAVES_UNBOUND,
    wontfix(
        'a file storing into exports is written as a CommonJS file, and an ES module storing into '
        'a name only the CommonJS wrapper binds is made up for the defect'
    ),
)
class TestAStoreIntoAWrapperNameAnEsModuleLeavesUnboundIsNotADeadStore(TestBase):
    pass


#: Node runs a file that declares a parameter of the CommonJS wrapper, here `module`, with `const`
#: at its top as an ES module. That is strict code, so a function called without a receiver gets
#: `undefined` for its `this`.
A_FILE_A_LEXICAL_WRAPPER_NAME_MAKES_AN_ES_MODULE = {
    'a const of a wrapper name every read of which is inlined': Program(
        a_program("""
            const module = function (a) { return a + 1; };
            console.log(module(1));
            console.log((function () { return typeof this; })());
            """),
        prints('2', 'undefined'),
        Reading.COMMONJS,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_FILE_A_LEXICAL_WRAPPER_NAME_MAKES_AN_ES_MODULE, backlog)
class TestTheDeclarationThatMakesAFileAnEsModuleStays(TestBase):
    pass


A_READ_OF_AN_ALIAS_THE_RUNNING_HOST_LACKS = {
    'function f() { return window; }\nf();\nconsole.log(1);\n': ('', 'ReferenceError'),
    'function f() { return self; }\nf();\nconsole.log(1);\n': ('', 'ReferenceError'),
    'function f() { return top; }\nf();\nconsole.log(1);\n': ('', 'ReferenceError'),
    'function f() { return frames; }\nf();\nconsole.log(1);\n': ('', 'ReferenceError'),
}


A_READ_OF_THE_ALIAS_ONLY_ANOTHER_HOST_LACKS = (
    'function f() { return global; }\nf();\nconsole.log(1);\n'
)


class TestABareGlobalObjectAliasIsNotCertainToResolve(TestBase):

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_a_read_of_an_alias_the_running_host_lacks_still_throws(self):
        rows = A_READ_OF_AN_ALIAS_THE_RUNNING_HOST_LACKS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            {source: (answer, answer) for source, answer in rows.items()},
        )

    def test_a_read_of_the_alias_the_running_host_defines_is_kept_all_the_same(self):
        self.assertEqual(
            folded(A_READ_OF_THE_ALIAS_ONLY_ANOTHER_HOST_LACKS),
            inspect.cleandoc(
                """
                global;
                console.log(1);
                """
            ),
        )


A_GLOBAL_PROPERTY_READ_THROUGH_A_SECOND_ALIAS = (
    'globalThis._V = 1;\nfunction f() { return global._V; }\nf();\nconsole.log(1);\n'
)

A_GLOBAL_PROPERTY_ESTABLISHED_BY_A_BARE_ASSIGNMENT = (
    'foo = 1;\nfunction f() { return global.foo; }\nf();\nconsole.log(1);\n'
)


class TestACrossAliasGlobalPropertyCollapseKeepsItsBaseThrow(TestBase):

    def test_a_property_read_through_a_second_alias_keeps_its_base_throw(self):
        self.assertEqual(
            folded(A_GLOBAL_PROPERTY_READ_THROUGH_A_SECOND_ALIAS),
            inspect.cleandoc(
                """
                globalThis._V = 1;
                global._V;
                console.log(1);
                """
            ),
        )

    def test_a_property_established_by_a_bare_assignment_keeps_its_base_throw(self):
        self.assertEqual(
            folded(A_GLOBAL_PROPERTY_ESTABLISHED_BY_A_BARE_ASSIGNMENT),
            inspect.cleandoc(
                """
                foo = 1;
                global.foo;
                console.log(1);
                """
            ),
        )


A_GLOBAL_PROPERTY_READ_THROUGH_A_RETURNED_THIS = {
    'globalThis.x = 1;\n'
    'var g = (function () { return this; })();\n'
    'console.log(g.x);\n': '1\n',
    'globalThis.x = 1;\n'
    'function f() { return this; }\n'
    'console.log(f().x);\n': '1\n',
}


class TestAGlobalObjectReturnedAsAFunctionsThisKeepsTheWritesReadThroughIt(TestBase):

    @todo
    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_a_write_read_back_through_a_returned_this_is_kept(self):
        rows = A_GLOBAL_PROPERTY_READ_THROUGH_A_RETURNED_THIS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


A_DEGENERATE_FINDER_THAT_THROWS_A_TYPEERROR = {
    'function g() { var o = null; return o.x || globalThis; }\nvar x = g();\nconsole.log(x);\n':
        'function g() {\n  return null.x || globalThis;\n}\nvar x = g();\nconsole.log(x);',
    'function g() { const k = globalThis; k = globalThis; return k; }\nvar x = g();\nconsole.log(x);\n':
        'function g() {\n  const k = globalThis;\n  k = globalThis;\n  return k;\n}'
        '\nvar x = g();\nconsole.log(x);',
    'function g() { const k = globalThis; k++; return k; }\nvar x = g();\nconsole.log(x);\n':
        'function g() {\n  const k = globalThis;\n  k++;\n  return k;\n}\nvar x = g();\nconsole.log(x);',
}


class TestADegenerateFinderThatThrowsATypeErrorIsKept(TestBase):

    @wontfix(
        'a global-object finder reads the names a host may give the global object; one that always '
        'throws a TypeError, reading a property of null or writing a constant, is made up for the defect'
    )
    def test_a_finder_whose_body_throws_a_typeerror_is_kept(self):
        rows = A_DEGENERATE_FINDER_THAT_THROWS_A_TYPEERROR
        self.assertEqual({source: folded(source) for source in rows}, rows)


A_FINDER_WHOSE_GLOBAL_RETURN_A_CAUGHT_THROW_SKIPS = inspect.cleandoc("""
    function g() { try { window.p; return self; } catch (e) {} }
    var x = g();
    console.log(typeof x);
""")

A_FINDER_RETURNING_A_NAME_WHOSE_GLOBAL_STORE_THREW = inspect.cleandoc("""
    function f() { var r; try { r = window; } catch (e) {} return r; }
    console.log(typeof f());
""")


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFinderWhoseGlobalReturnACaughtThrowSkipsIsKept(TestBase):

    @backlog
    def test_a_finder_whose_global_return_is_skipped_by_a_caught_throw_is_kept(self):
        source = A_FINDER_WHOSE_GLOBAL_RETURN_A_CAUGHT_THROW_SKIPS
        self.assertEqual(before_and_after(source), (('undefined\n', None), ('undefined\n', None)))

    @backlog
    def test_a_finder_returning_a_name_whose_global_store_threw_is_kept(self):
        source = A_FINDER_RETURNING_A_NAME_WHOSE_GLOBAL_STORE_THREW
        self.assertEqual(before_and_after(source), (('undefined\n', None), ('undefined\n', None)))


A_FINDER_WHOSE_LOCAL_HOLDS_THE_GLOBAL_OBJECT_ONLY_FOR_A_WHILE: dict[str, Program] = {
    'a store of another value after the global object, in an arrow': Program(
        a_program("""
            function finder() {
              var fs = [(g) => ((g = globalThis) && (g = 1)) || g];
              return fs[0]();
            }
            var G = finder();
            console.log(G === globalThis);
            """),
        prints('false'),
    ),
    'an update after the global object is stored': Program(
        a_program("""
            function finder() { var g = globalThis; g++; return g; }
            var G = finder();
            console.log(G === globalThis);
            """),
        prints('false'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFinderWhoseLocalHoldsTheGlobalObjectOnlyForAWhileIsKept(TestBase):

    @wontfix(
        'a finder stores the global object into its local and returns it; none stores another '
        'value into that local afterwards or updates it, and the form a real finder takes, a '
        'store that threw, is tracked by TestAFinderWhoseGlobalReturnACaughtThrowSkipsIsKept'
    )
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        for label, row in A_FINDER_WHOSE_LOCAL_HOLDS_THE_GLOBAL_OBJECT_ONLY_FOR_A_WHILE.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())


A_FINDER_RUNNING_CODE_THAT_WRITES_OUTSIDE_IT: dict[str, Program] = {
    'a getter of an object literal': Program(
        a_program("""
            var hits = 0;
            function getGlobal() {
              var h = globalThis;
              try { ({ get x() { hits = hits + 1; return 0; } }).x; } catch (e) {}
              return h;
            }
            var G = getGlobal();
            console.log(G === globalThis, hits);
            """),
        prints('true 1'),
        Reading.SCRIPT,
    ),
    'a function written inline and run through call': Program(
        a_program("""
            var hits = 0;
            function getGlobal() {
              var h = globalThis;
              try { (function () { hits = hits + 1; }).call(null); } catch (e) {}
              return h;
            }
            var G = getGlobal();
            console.log(G === globalThis, hits);
            """),
        prints('true 1'),
        Reading.SCRIPT,
    ),
    'a function written inline and run as the tag of a template': Program(
        a_program("""
            var hits = 0;
            function getGlobal() {
              var h = globalThis;
              try { (function () { hits = hits + 1; })`x`; } catch (e) {}
              return h;
            }
            var G = getGlobal();
            console.log(G === globalThis, hits);
            """),
        prints('true 1'),
        Reading.SCRIPT,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFinderRunningCodeThatWritesOutsideItIsKept(TestBase):

    @wontfix(
        'a finder reads the names a host may give the global object, in a try block or a test; '
        'none runs a getter, a call through call or a tagged template that writes outside it'
    )
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        for label, row in A_FINDER_RUNNING_CODE_THAT_WRITES_OUTSIDE_IT.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())


A_STORE_SKIPPED_BEFORE_A_CATCH_LEAVES_FOR_THE_FINALLY = {
    inspect.cleandoc("""
        function f() {
          var r = 1;
          try { window; r = 5; } catch (e) { throw e; } finally { console.log(r); }
        }
        try { f(); } catch (e) {}
    """): '1\n',
    inspect.cleandoc("""
        function f() {
          var r;
          try { window; r = 5; } catch (e) { return; } finally { console.log(r); }
        }
        f();
    """): 'undefined\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAStoreSkippedBeforeACatchLeavesIsNotDoneInTheFinally(TestBase):

    def test_the_finally_reads_the_value_from_before_the_store(self):
        rows = A_STORE_SKIPPED_BEFORE_A_CATCH_LEAVES_FOR_THE_FINALLY
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


AN_INDIRECT_EVAL_THROUGH_A_HOST_CONDITIONAL_ALIAS = "window.eval('console.log(1);');\n"


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnIndirectEvalThroughAHostConditionalAliasKeepsItsBaseThrow(TestBase):

    def test_an_indirect_eval_through_a_host_conditional_alias_is_kept(self):
        source = AN_INDIRECT_EVAL_THROUGH_A_HOST_CONDITIONAL_ALIAS
        self.assertEqual(before_and_after(source), (('', 'ReferenceError'), ('', 'ReferenceError')))


#: `typeof` throws for a binding in its dead zone, although it answers `'undefined'` for a name
#: nothing binds.
A_READ_IN_THE_DEAD_ZONE_OF_A_LEXICAL_BINDING = {
    'function f() { let v = q; let q = 1; }\n'
    'f();\nconsole.log(1);\n': ('', 'ReferenceError'),

    'function f() { let v = 0; v = q; const q = 1; }\n'
    'f();\nconsole.log(1);\n': ('', 'ReferenceError'),

    'function f() { { let v = typeof q; let q = 1; } }\n'
    'f();\nconsole.log(1);\n': ('', 'ReferenceError'),

    '{ let v = q; let q = 1; }\nconsole.log(1);\n': ('', 'ReferenceError'),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAReadOfALexicalBindingBeforeItsDeclarationThrows(TestBase):

    def test_a_read_before_the_declaration_runs_still_throws(self):
        rows = A_READ_IN_THE_DEAD_ZONE_OF_A_LEXICAL_BINDING
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            {source: (answer, answer) for source, answer in rows.items()},
        )


A_DEAD_ZONE_READ_REACHED_THROUGH_A_CALL = {
    'function f() { return q; }\nvar dead = f();\nlet q = 1;\nconsole.log(2);\n': ('', 'ReferenceError'),
    'function f() { return q; }\nvar dead = f();\nconst q = 1;\nconsole.log(2);\n': ('', 'ReferenceError'),
    'var g = () => q;\nvar dead = g();\nlet q = 1;\nconsole.log(2);\n': ('', 'ReferenceError'),
    'function g() { return q; }\nfunction f() { return g(); }\n'
    'var dead = f();\nlet q = 1;\nconsole.log(2);\n': ('', 'ReferenceError'),
    'var g = () => q;\nvar f = () => g();\n'
    'var dead = f();\nlet q = 1;\nconsole.log(2);\n': ('', 'ReferenceError'),
    'function f() { return C; }\nvar dead = f();\nclass C {}\nconsole.log(2);\n': ('', 'ReferenceError'),
    'function f() { return this && q; }\nvar dead = f();\nlet q = 1;\nconsole.log(2);\n': ('', 'ReferenceError'),
    'function f() { return this && q; }\nvar dead = f();\nconst q = 1;\nconsole.log(2);\n': ('', 'ReferenceError'),
    'var g = () => this && q;\nvar dead = g();\nlet q = 1;\nconsole.log(2);\n': ('', 'ReferenceError'),
    'function g() { return this && q; }\nfunction f() { return g(); }\n'
    'var dead = f();\nlet q = 1;\nconsole.log(2);\n': ('', 'ReferenceError'),
    'var g = () => this && q;\nvar f = () => g();\n'
    'var dead = f();\nlet q = 1;\nconsole.log(2);\n': ('', 'ReferenceError'),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestADeadZoneReadReachedThroughACallStillThrows(TestBase):

    def test_a_dead_store_call_to_a_dead_zone_reader_still_throws(self):
        rows = A_DEAD_ZONE_READ_REACHED_THROUGH_A_CALL
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            {source: (answer, answer) for source, answer in rows.items()},
        )


A_DEAD_ASSIGNMENT_TO_A_DEAD_ZONE_READER = {
    'function f() { return this && q; }\nvar x;\nx = f();\nlet q = 1;\nconsole.log(2);\n': ('', 'ReferenceError'),
    'function f() { return this && q; }\nvar x;\nx = [f()];\nlet q = 1;\nconsole.log(2);\n': ('', 'ReferenceError'),
    'function g() { return this && q; }\nfunction f() { return g(); }\n'
    'var x;\nx = f();\nlet q = 1;\nconsole.log(2);\n': ('', 'ReferenceError'),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestADeadAssignmentToADeadZoneReaderStillThrows(TestBase):

    @backlog
    def test_a_dead_assignment_call_to_a_dead_zone_reader_still_throws(self):
        rows = A_DEAD_ASSIGNMENT_TO_A_DEAD_ZONE_READER
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            {source: (answer, answer) for source, answer in rows.items()},
        )


A_FOLDED_MEMBER_BASE_IN_A_DEAD_ZONE = {
    'function f() { return o.x; }\nf();\nlet o = { x: 1 };\nconsole.log(2);\n': ('', 'ReferenceError'),
    'var y = (function () { return o.x; })();\nlet o = { x: 1 };\nconsole.log(2);\n': ('', 'ReferenceError'),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFoldedMemberBaseReadInADeadZoneStillThrows(TestBase):

    @backlog
    def test_a_folded_member_base_read_before_its_declaration_still_throws(self):
        rows = A_FOLDED_MEMBER_BASE_IN_A_DEAD_ZONE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            {source: (answer, answer) for source, answer in rows.items()},
        )


A_WRITE_IN_THE_DEAD_ZONE_OF_A_LEXICAL_BINDING = {
    '{ x = 5; let x; }\nconsole.log(1);\n': ('', 'ReferenceError'),
    'function f() { q = 5; let q = 1; }\nf();\nconsole.log(1);\n': ('', 'ReferenceError'),
    'function f() { q = 5; }\nvar dead = f();\nlet q = 1;\nconsole.log(2);\n': ('', 'ReferenceError'),
    'function f() { q = 5; }\nvar dead = f();\nconst q = 1;\nconsole.log(2);\n': ('', 'ReferenceError'),
    'function g() { q = 5; }\nfunction f() { g(); }\n'
    'var dead = f();\nlet q = 1;\nconsole.log(2);\n': ('', 'ReferenceError'),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAWriteInTheDeadZoneOfALexicalBindingStillThrows(TestBase):

    @backlog
    def test_a_write_before_the_declaration_runs_still_throws(self):
        rows = A_WRITE_IN_THE_DEAD_ZONE_OF_A_LEXICAL_BINDING
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            {source: (answer, answer) for source, answer in rows.items()},
        )


#: A `__proto__` key written with a colon, quoted or not, sets the prototype of the object and gives
#: it no property; the shorthand `{ __proto__ }` gives it an ordinary property.
AN_OBJECT_LITERAL_SPELLING_PROTO = {
    'var __proto__ = 7; console.log(Object.keys({ __proto__ }).length);': '1\n',
    "console.log(Object.keys({ '__proto__': 7 }).length);": '0\n',
    'console.log(Object.keys({ __proto__: 1 }).length);': '0\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnObjectLiteralSpellingProtoIsCounted(TestBase):

    @opportunity
    def test_an_object_literal_spelling_proto_folds_to_the_count_it_has(self):
        rows = AN_OBJECT_LITERAL_SPELLING_PROTO
        self.assertEqual(
            {source: folded(source) for source in rows},
            {source: F'console.log({prints.strip()});' for source, prints in rows.items()},
        )


#: A property installed by `Object.defineProperty` without `enumerable` is not enumerable, so no
#: `for-in` walk visits it, and a walk visits an own key once although the chain holds the same
#: name.
A_WALK_A_WRITTEN_CHAIN_STILL_DECIDES = {
    'Object.defineProperty(Object.prototype, "z", {value: 9});': ('{a: 1}', 'a'),
    an_accessor_at('Object.prototype', 'z'): ('{a: 1}', 'a'),
    'delete Object.prototype.toString;': ('{a: 1}', 'a'),
    'Object.prototype.z = 9;': ('{z: 1, a: 2}', 'za'),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAWalkAWrittenChainStillDecidesIsStillWalked(TestBase):

    @opportunity
    def test_a_walk_a_written_chain_still_decides_is_folded_beside_the_write(self):
        rows = A_WALK_A_WRITTEN_CHAIN_STILL_DECIDES
        self.assertEqual(
            {install: folded(a_walk_of(receiver, install)) for install, (receiver, _) in rows.items()},
            {install: on_separate_lines(printed(install), F"console.log('{names}');") for install, (_, names) in rows.items()},
        )


A_READ_A_WRITTEN_CHAIN_DOES_NOT_REACH = {
    'Object.prototype.z = 9; var o = {}; o.z = 1; console.log(o.z);':
        'Object.prototype.z = 9;\nconsole.log(1);',
    "Object.prototype.q = 1; var o = {}; console.log('toString' in o);":
        'Object.prototype.q = 1;\nconsole.log(true);',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAReadAWrittenChainDoesNotReachIsStillAnswered(TestBase):

    @opportunity
    def test_a_read_a_written_chain_does_not_reach_is_folded(self):
        rows = A_READ_A_WRITTEN_CHAIN_DOES_NOT_REACH
        self.assertEqual(
            {source: folded(source) for source in rows},
            A_READ_A_WRITTEN_CHAIN_DOES_NOT_REACH,
        )


#: `String(-0)` is `'0'`, so `'a' + -0` is `'a0'`.
A_CONCATENATION_WITH_A_UNARY_OPERATOR_OVER_A_LITERAL = {
    "'x' + -1": 'x-1',
    "'a' + -0": 'a0',
    "'' + !0": 'true',
    "'' + void 0": 'undefined',
}


class TestTheStaticStringReadsEveryConcatenationTheFoldCollapses(TestBase):

    def test_the_fold_collapses_each_concatenation_to_its_string(self):
        rows = A_CONCATENATION_WITH_A_UNARY_OPERATOR_OVER_A_LITERAL
        self.assertEqual(
            {source: folded(F'SINK({source});') for source in rows},
            {source: F"SINK('{text}');" for source, text in rows.items()},
        )

    @opportunity
    def test_the_static_string_reads_each_concatenation_as_its_string(self):
        rows = A_CONCATENATION_WITH_A_UNARY_OPERATOR_OVER_A_LITERAL
        self.assertEqual(
            {source: static_string(JsParser(F'({source});').parse().body[0].expression) for source in rows},
            rows,
        )


AN_OBJECT_A_BUILTIN_TAKES_WITHOUT_CONVERTING_IT = {
    a_program("""
        function f() { return Object.keys({toString: 1, a: 2}).length; }
        console.log(f());
        """): 'console.log(2);',
    a_program("""
        function f() { var a = []; return a.push({valueOf: 1}); }
        console.log(f());
        """): 'console.log(1);',
    a_program("""
        function f() { var o = {toString: function () { return 'x'; }}; return [o].indexOf(o); }
        console.log(f());
        """): 'console.log(0);',
}


class TestABuiltinThatConvertsNoArgumentFoldsOverAnyObject(TestBase):

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_prints_for_each_text_what_it_prints_for_the_program(self):
        rows = AN_OBJECT_A_BUILTIN_TAKES_WITHOUT_CONVERTING_IT
        self.assertEqual(
            {source: behavior(source) for source in rows},
            {source: behavior(text) for source, text in rows.items()},
        )

    @opportunity
    def test_each_program_is_folded(self):
        rows = AN_OBJECT_A_BUILTIN_TAKES_WITHOUT_CONVERTING_IT
        self.assertEqual({source: folded(source) for source in rows}, rows)


AN_ELEMENT_AN_ARRAY_METHOD_CONVERTS_THROUGH_A_REPLACED_CHAIN = {
    'an object joined': Program(
        inspect.cleandoc('''
            Object.prototype.toString = function () { return 'x'; };
            function f() { return [{}].join(''); }
            console.log(f());
        '''),
        prints('x'),
        Reading.SCRIPT,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(AN_ELEMENT_AN_ARRAY_METHOD_CONVERTS_THROUGH_A_REPLACED_CHAIN, backlog)
class TestAnArrayMethodConvertingAnElementConsultsTheChainThatConvertsIt(TestBase):
    pass


A_FUNCTION_A_BUILTIN_CONVERTS_THROUGH_ITS_OWN_TOSTRING = {
    'an array joining it': Program(
        inspect.cleandoc('''
            function W(a) { return a + 1; }
            W.toString = function () { return "x"; };
            function f() { return [W].join(''); }
            console.log(f());
        '''),
        prints('x'),
    ),
    'a computed key': Program(
        inspect.cleandoc('''
            function W(a) { return a + 1; }
            W.toString = function () { return "x"; };
            function f() { return Object.keys({ [W]: 1 })[0]; }
            console.log(f());
        '''),
        prints('x'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_FUNCTION_A_BUILTIN_CONVERTS_THROUGH_ITS_OWN_TOSTRING, backlog)
class TestABuiltinConvertingAFunctionRunsItsOwnToString(TestBase):
    pass


A_FUNCTION_HANDED_ON_WHERE_THE_FOLD_DOES_NOT_REACH = {
    'converted at the top level': Program(
        inspect.cleandoc('''
            function W(a) { return a + 1; }
            console.log(String(W));
        '''),
        prints('function W(a) { return a + 1; }'),
    ),
    'read from a top-level array inside a function': Program(
        inspect.cleandoc('''
            function W(a) { return a + 1; }
            var g = [W];
            function f() { return String(g[0]); }
            console.log(f());
        '''),
        prints('function W(a) { return a + 1; }'),
    ),
    'handed to a timer': Program(
        inspect.cleandoc('''
            function W(a) { return a + 1; }
            setTimeout(W, 0);
            function f() { return String(W); }
            console.log(f());
        '''),
        prints('function W(a) { return a + 1; }'),
    ),
    'a method of an object handed on': Program(
        inspect.cleandoc('''
            var o = { m: function (a) { return a + 1; } };
            var g = [o];
            console.log(g.length);
            function f() { return String(o.m); }
            console.log(f());
        '''),
        prints('1', 'function (a) { return a + 1; }'),
    ),
    'a member of a namespace': Program(
        inspect.cleandoc('''
            var NS = {};
            NS.W = function (a) { return a + 1; };
            function f() { var g = [NS.W]; return String(g[0]); }
            console.log(f());
        '''),
        prints('function (a) { return a + 1; }'),
    ),
    'with rest parameters': Program(
        inspect.cleandoc('''
            function W(...args) { return args[0] + 1; }
            function f() { var g = [W]; return String(g[0]); }
            console.log(f());
        '''),
        prints('function W(...args) { return args[0] + 1; }'),
    ),
    'beside a class-inheritance helper': Program(
        inspect.cleandoc('''
            function W(a) { return a + 1; }
            var g = [W];
            console.log(g.length);
            var __extends = (this && this.__extends) || (function () {
                var extendStatics = function (d, b) {
                    extendStatics = Object.setPrototypeOf ||
                        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
                        function (d, b) { for (var p in b) if (Object.prototype.hasOwnProperty.call(b, p)) d[p] = b[p]; };
                    return extendStatics(d, b);
                };
                return function (d, b) {
                    extendStatics(d, b);
                    function __() { this.constructor = d; }
                    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
                };
            })();
            var Animal = (function () { function Animal() { this.legs = 4; } return Animal; }());
            var Dog = (function (_super) {
                __extends(Dog, _super);
                function Dog() { return _super.call(this) || this; }
                return Dog;
            }(Animal));
            console.log(new Dog().legs);
            function f() { return String(W); }
            console.log(f());
        '''),
        prints('1', '4', 'function W(a) { return a + 1; }'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_FUNCTION_HANDED_ON_WHERE_THE_FOLD_DOES_NOT_REACH, todo)
class TestAFunctionHandedOnIsConvertedToItsWrittenTextWhereNoFoldReachesIt(TestBase):
    pass


A_FUNCTION_GIVEN_A_CONVERSION_UNDER_A_KEY_KNOWN_ONLY_AT_RUNTIME = {
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        g[0][["to", "Str", "ing"].join(process.argv[9] || "")] = function () { return "x"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        g[0][process.argv[9] || "toString"] = function () { return "x"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        g[0][["toString"]] = function () { return "x"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var _a = ["valueOf", "toString"];
        (function (arr, n) { while (--n) { arr.push(arr.shift()); } })(_a, 2);
        function _b(i) { return _a[i]; }
        g[0][_b(0)] = function () { return "x"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        for (var k of ["toString"]) { g[0][k] = function () { return "x"; }; }
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        ["toString"].forEach(function (k) { g[0][k] = function () { return "x"; }; });
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function put(o, k, v) { o[k] = v; }
        put.call(null, g[0], "toString", function () { return "x"; });
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    guarded(NAME_OF, 'nameOf', 5, NAME_OF_5, inspect.cleandoc('''
        var keep = [nameOf];
        function W(a) { return a + 1; }
        var g = [W];
        g[0][guarded({ name: "toString" })] = function () { return "x"; };
        function f() { return String(W); }
        console.log(f());
    ''') + '\n'):
        'x\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFunctionGivenAConversionUnderAKeyKnownOnlyAtRuntimeIsConvertedByIt(TestBase):

    @wontfix(
        'no obfuscated file gives a function it hands on a conversion method under a key the run '
        'cannot read: these keys are joined from pieces, read from the command line, wrapped in an '
        'array, rotated by hand where the run never decodes the table, taken by a loop or a '
        'callback, handed to a helper through call, or returned by a guarded decoder the run never '
        'decodes, all made up for the defect'
    )
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        rows = A_FUNCTION_GIVEN_A_CONVERSION_UNDER_A_KEY_KNOWN_ONLY_AT_RUNTIME
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


A_FUNCTION_GIVEN_A_CONVERSION_THROUGH_A_MADE_UP_INSTALLER = {
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        Object.getOwnPropertyDescriptor(Object.prototype, "__proto__").set.call(g[0], { toString() { return "d"; } });
        function f() { return String(W); }
        console.log(f());
    '''):
        'd\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        Object.prototype.__lookupSetter__("__proto__").call(g[0], { toString() { return "q"; } });
        function f() { return String(W); }
        console.log(f());
    '''):
        'q\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        Reflect.get(Object, "defineProperty")(g[0], "toString", { value: function () { return "d"; } });
        function f() { return String(W); }
        console.log(f());
    '''):
        'd\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        Object[process.argv[9] || "defineProperty"].call(Object, W, "toString", { value: function () { return "d"; } });
        function f() { return String(W); }
        console.log(f());
    '''):
        'd\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        Object[process.argv[9] || "defineProperty"].apply(Object, [W, "toString", { value: function () { return "d"; } }]);
        function f() { return String(W); }
        console.log(f());
    '''):
        'd\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var m = Object[process.argv[9] || "defineProperty"];
        m(W, "toString", { value: function () { return "d"; } });
        function f() { return String(W); }
        console.log(f());
    '''):
        'd\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFunctionGivenAConversionThroughAMadeUpInstallerIsConvertedByIt(TestBase):

    @wontfix(
        'no obfuscated file reaches an installer this way: the __proto__ setter taken from its '
        'descriptor or through __lookupSetter__, defineProperty taken with Reflect.get, and an '
        'installer taken under a key known only at runtime and called through call, apply or a '
        'name are made up for the defect'
    )
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        rows = A_FUNCTION_GIVEN_A_CONVERSION_THROUGH_A_MADE_UP_INSTALLER
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


A_FUNCTION_PROTOTYPE_REACHED_THROUGH_A_FUNCTION_LITERAL = {
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        Object.getPrototypeOf(function () {}).toString = function () { return "x"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        (function () {}).__proto__.toString = function () { return "x"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFunctionPrototypeReachedThroughAFunctionLiteralIsSeen(TestBase):

    @wontfix(
        'no obfuscated file reaches Function.prototype through the prototype or __proto__ of a '
        'function literal, and the other folds decline the same shape for the same reason'
    )
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        rows = A_FUNCTION_PROTOTYPE_REACHED_THROUGH_A_FUNCTION_LITERAL
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

A_FUNCTION_HANDED_ON_BESIDE_A_CONVERSION_ON_A_VALUE_READ_AS_ANY_FUNCTION = {
    'a prototype replaced by an object literal': Program(
        inspect.cleandoc('''
            function W(a) { return a + 1; }
            function Foo() {}
            Foo.prototype = { bar: 1 };
            Foo.prototype.toString = function () { return "foo"; };
            console.log(String(new Foo()));
            function f() { var g = [W]; return String(g[0]); }
            console.log(f());
        '''),
        prints('foo', 'function W(a) { return a + 1; }'),
    ),
    'a prototype replaced by Object.create': Program(
        inspect.cleandoc('''
            function W(a) { return a + 1; }
            function Base() {}
            function Foo() {}
            Foo.prototype = Object.create(Base.prototype);
            Foo.prototype.toString = function () { return "foo"; };
            console.log(String(new Foo()));
            function f() { var g = [W]; return String(g[0]); }
            console.log(f());
        '''),
        prints('foo', 'function W(a) { return a + 1; }'),
    ),
}

A_FUNCTION_HANDED_ON_BESIDE_A_CONVERSION_ON_A_BOUND_FUNCTION = {
    'a bound function': Program(
        inspect.cleandoc('''
            function W(a) { return a + 1; }
            var log = console.log.bind(console);
            log.toString = function () { return "log"; };
            console.log(String(log));
            function f() { var g = [W]; return String(g[0]); }
            console.log(f());
        '''),
        prints('log', 'function W(a) { return a + 1; }'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_FUNCTION_HANDED_ON_BESIDE_A_CONVERSION_ON_A_VALUE_READ_AS_ANY_FUNCTION, todo)
class TestAFunctionHandedOnConvertsToItsWrittenTextBesideAConversionOnAValueReadAsAnyFunction(TestBase):
    pass


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_FUNCTION_HANDED_ON_BESIDE_A_CONVERSION_ON_A_BOUND_FUNCTION, backlog)
class TestAFunctionHandedOnConvertsToItsWrittenTextBesideAConversionOnABoundFunction(TestBase):
    pass


A_NAME_A_GLOBAL_WRITE_UNDER_A_RUNTIME_KEY_REPLACES = {
    'a call': Program(
        inspect.cleandoc('''
            function W(a) { return a + 1; }
            function setGlobal(name, value) { globalThis[name] = value; }
            setGlobal("W", function () { return 9; });
            function f() { return W(1); }
            console.log(f());
        '''),
        prints('9'),
        Reading.SCRIPT,
    ),
    'a conversion': Program(
        inspect.cleandoc('''
            function W(a) { return a + 1; }
            function setGlobal(name, value) { globalThis[name] = value; }
            setGlobal("W", 5);
            function f() { return String(W); }
            console.log(f());
        '''),
        prints('5'),
        Reading.SCRIPT,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_NAME_A_GLOBAL_WRITE_UNDER_A_RUNTIME_KEY_REPLACES, todo)
class TestANameAGlobalWriteUnderARuntimeKeyReplacesIsNotReadAsItsDeclaration(TestBase):
    pass


A_FUNCTION_HANDED_ON_BESIDE_AN_INSTALLER_USED_AS_A_TAG = {
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        Object.assign`x`;
        function f() { var g = [W]; return String(g[0]); }
        console.log(f());
    '''):
        'function W(a) { return a + 1; }\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFunctionHandedOnBesideAnInstallerUsedAsATagConvertsToItsWrittenText(TestBase):

    @wontfix('no program calls an installer as the tag of a template, which passes it the strings of the template')
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        rows = A_FUNCTION_HANDED_ON_BESIDE_AN_INSTALLER_USED_AS_A_TAG
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestABuiltinTheProgramReplacedIsNotFoldedAsTheIntrinsic(TestBase):

    def test_a_bare_global_written_on_the_global_object_is_not_folded_as_the_builtin(self):
        source = (
            "globalThis['parseInt'] = function () { return 42; };\n"
            "console.log(parseInt('7'));"
        )
        self.assertEqual(Reading.SCRIPT.read(source), (prints('42'), prints('42')))

    def test_a_literal_receivers_method_survives_a_rebind_of_the_intrinsic_name(self):
        source = "Array = {};\nconsole.log([1, 2, 3].join('-'));"
        self.assertEqual(Reading.SCRIPT.read(source), (prints('1-2-3'), prints('1-2-3')))


A_PROTOTYPE_REACHED_THROUGH_A_BINDING = {
    'var a = {}; a.__proto__.z = 9; var o = {}; console.log(o.z);':
        '9\n',
    'var a = {}; var g = Object.getPrototypeOf; g(a).z = 9; var o = {}; console.log(o.z);':
        '9\n',
    'function f(b) { b.__proto__.join = function () { return "X"; }; }'
    ' f([]); console.log([1, 2].join("-"));':
        'X\n',
    'function f(b) { b.__proto__.slice = function () { this[0] = 9; return this; }; }'
    ' f([]); var a = [1, 2]; a.slice(0); console.log(a[0]);':
        '9\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAPrototypeReachedThroughABindingIsStillWritten(TestBase):

    @wontfix(
        'no obfuscator and no program writes a built-in prototype through the __proto__ of a variable '
        'or a parameter, or through an alias of getPrototypeOf; the shapes are made up for the defect'
    )
    def test_a_prototype_reached_through_a_binding_answers_the_read(self):
        rows = A_PROTOTYPE_REACHED_THROUGH_A_BINDING
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


A_PROTOTYPE_HANDED_TO_SOMETHING_THAT_WRITES_IT = {
    'Object.assign(Object.prototype, {z: 9}); var o = {}; console.log(o.z);':
        '9\n',
    'Reflect.set(Object.prototype, "z", 9); var o = {}; console.log(o.z);':
        '9\n',
    'Reflect.deleteProperty(Object.prototype, "toString");\n'
    + evaluated_in_a_body('{a: 1}', "'toString' in v"):
        'false\n',
    'function patch(p) { p.z = 9; } patch(Object.prototype); var o = {}; console.log(o.z);':
        '9\n',
    'function patch(o) { o.prototype.zz = 9; }\npatch(Object);\n'
    + evaluated_in_a_body('{a: 1}', 'v.zz'):
        '9\n',
    r'(function (O) { O.prototype[Symbol.toPrimitive] = function () { return "\n"; }; })(Object);' '\n'
    + checked():
        'tampered\nran\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAPrototypeHandedToAWriterIsStillWritten(TestBase):

    @backlog
    def test_a_prototype_handed_to_a_writer_answers_the_read(self):
        rows = A_PROTOTYPE_HANDED_TO_SOMETHING_THAT_WRITES_IT
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


A_PROTOTYPE_A_METHOD_RETURNS = {
    'var A = {f: function () { return Object.prototype; }};'
    ' var P = A.f(); P.p = 1; var B = {q: 2}; console.log(B.p);':
        '1\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAPrototypeAMethodReturnsIsStillWrittenByItsCaller(TestBase):

    @wontfix('no obfuscator and no program writes Object.prototype through the result of a method returning it')
    def test_a_prototype_a_method_returns_answers_the_read(self):
        rows = A_PROTOTYPE_A_METHOD_RETURNS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


A_PROTOTYPE_WRITTEN_THROUGH_THE_GLOBAL_OBJECT = {
    'global.Object.prototype.k = 1; var B = {x: 1}; console.log(B.k);':
        '1\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAPrototypeWrittenThroughTheGlobalObjectIsStillWritten(TestBase):

    @backlog
    def test_a_prototype_written_through_the_global_object_answers_the_read(self):
        rows = A_PROTOTYPE_WRITTEN_THROUGH_THE_GLOBAL_OBJECT
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


AN_ACCESSOR_ON_A_BUILT_IN_READ_BARE = {
    'Object.defineProperty(Math, "floor", {get: function () { console.log("ran"); return Math.round; }});'
    ' Math.floor; console.log(1);':
        'ran\n1\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnAccessorInstalledOnABuiltInRunsWhereItIsRead(TestBase):

    @wontfix(
        'programs and obfuscators replace a built-in method by assigning it, which the flag sees; '
        'none installs a getter on a built-in and reads the method bare for what the getter does'
    )
    def test_a_getter_installed_on_a_built_in_runs_where_it_is_read(self):
        rows = AN_ACCESSOR_ON_A_BUILT_IN_READ_BARE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


A_BUILT_IN_REPLACED_WITHOUT_SPELLING_ITS_NAME = {
    inspect.cleandoc("""
        Object.getPrototypeOf(new Date()).getTime = function () { return 5000000000000; };
        console.log(new Date().getTime() > 4102444800000);
    """): 'true\n',
    inspect.cleandoc("""
        (new Date()).__proto__.getTime = function () { return 5000000000000; };
        console.log(new Date().getTime() > 4102444800000);
    """): 'true\n',
    inspect.cleandoc("""
        var d = new Date();
        Object.getPrototypeOf(d).getTime = function () { return 5000000000000; };
        console.log(new Date().getTime() > 4102444800000);
    """): 'true\n',
    inspect.cleandoc("""
        function patch(x) {
          x.__proto__.getTime = function () { return 5000000000000; };
        }
        patch(new Date());
        console.log(new Date().getTime() > 4102444800000);
    """): 'true\n',
    inspect.cleandoc("""
        Object.getPrototypeOf('').toUpperCase = function () { return 'replaced'; };
        console.log('a'.toUpperCase());
    """): 'replaced\n',
    inspect.cleandoc("""
        var s = 'x';
        Object.getPrototypeOf(s).toUpperCase = function () { return 'replaced'; };
        console.log('a'.toUpperCase());
    """): 'replaced\n',
    inspect.cleandoc("""
        var {constructor: S} = '';
        S.prototype.toUpperCase = function () { return 'replaced'; };
        console.log('a'.toUpperCase());
    """): 'replaced\n',
    inspect.cleandoc("""
        var {__proto__: p} = [];
        p.join = function () { return '5'; };
        console.log(+[]);
    """): '5\n',
    inspect.cleandoc("""
        var k = ['Da', 'te'].join('');
        globalThis[k].now = function () { return 5e12; };
        console.log(Date.now() > 4102444800000);
    """): 'true\n',
    inspect.cleandoc("""
        var k = ['Ma', 'th'].join('');
        globalThis[k].floor = function () { return 42; };
        console.log(Math.floor(1.5));
    """): '42\n',
    inspect.cleandoc("""
        require('vm').runInThisContext('Date.now = function () { return 5000000000000; };');
        console.log(Date.now() > 4102444800000);
    """): 'true\n',
    inspect.cleandoc("""
        require('vm').runInThisContext('Math.floor = function () { return 42; };');
        console.log(Math.floor(1.5));
    """): '42\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestABuiltInReplacedWithoutSpellingItsNameIsNotFolded(TestBase):

    @wontfix(
        'no obfuscator and no program replaces a built-in this way: a prototype reached from an '
        'instance or a string, a global under a key joined at runtime and the vm module are made up '
        'for the defect, and attributing them would refuse every write to a property of the result '
        'of a call'
    )
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        rows = A_BUILT_IN_REPLACED_WITHOUT_SPELLING_ITS_NAME
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


A_PROTOTYPE_WRITTEN_THROUGH_THE_RESULT_OF_A_CALL = {
    "Reflect.get(Object(''), '__proto__').nope = 5; console.log('abc'.nope);": '5\n',
    '[].__proto__.valueOf().nope = 5; console.log([].nope);': '5\n',
    "var gp = Object.getPrototypeOf; gp('').nope = 5; console.log('abc'.nope);": '5\n',
    "Object.getPrototypeOf.call(0, '').nope = 5; console.log('abc'.nope);": '5\n',
    "({}).__lookupGetter__('__proto__').call('').nope = 5; console.log('abc'.nope);": '5\n',
}

A_PROTOTYPE_WRITTEN_THROUGH_A_PROPERTY_OF_THE_GLOBAL_OBJECT = {
    "var p = ''.__proto__; globalThis['p'].nope = 5; console.log('abc'.nope);": '5\n',
}

A_PROTOTYPE_WRITTEN_THROUGH_A_NAME_HOLDING_A_CONSTRUCTOR = {
    "var {'String': S} = globalThis; S.prototype.zz = 5; console.log('abc'.zz);": '5\n',
    "var o = Object; var m = (o ||= 0); m.prototype.nope = 1; console.log(({}).nope, [].nope, 'abc'.nope);": '1 1 1\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAPrototypeWrittenThroughAValueTheGuardDoesNotFollowIsNotFolded(TestBase):

    @wontfix(
        'no obfuscator and no program writes a prototype it reaches through Reflect.get, an aliased '
        'getPrototypeOf or a property of the global object; reading every call result as a possible '
        'built-in would refuse the folds in every script that writes a property of what a call '
        'returns'
    )
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        rows = A_PROTOTYPE_WRITTEN_THROUGH_THE_RESULT_OF_A_CALL
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    @wontfix(
        'no obfuscator and no program writes a prototype it reaches through a property of the '
        'global object that a top-level var holds'
    )
    def test_the_deobfuscation_of_a_classic_script_prints_what_it_prints(self):
        rows = A_PROTOTYPE_WRITTEN_THROUGH_A_PROPERTY_OF_THE_GLOBAL_OBJECT
        self.assertEqual(
            {source: before_and_after_in_a_host(source) for source in rows},
            each_program_still_prints(rows),
        )

    @wontfix(
        'no obfuscator and no program writes a prototype through a constructor it destructures off '
        'the global object or keeps in a name through a logical assignment'
    )
    def test_the_deobfuscation_of_a_write_through_a_name_holding_a_constructor_prints_what_it_prints(self):
        rows = A_PROTOTYPE_WRITTEN_THROUGH_A_NAME_HOLDING_A_CONSTRUCTOR
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


A_PROTOTYPE_WRITTEN_BY_ITS_OWN_METHOD_AND_READ_IN_A_FUNCTION = {
    'Array.prototype.push(5); function f() { return [][0]; } console.log(f());': '5\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAPrototypeWrittenByItsOwnMethodIsReadInAFunctionTheEvaluatorRuns(TestBase):

    @wontfix('no obfuscator and no program stores an element on Array.prototype through its own push')
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        rows = A_PROTOTYPE_WRITTEN_BY_ITS_OWN_METHOD_AND_READ_IN_A_FUNCTION
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


class TestAPropertyNamedLikeABuiltInLeavesTheBuiltInTrusted(TestBase):

    @opportunity
    def test_a_check_of_the_clock_folds_beside_a_property_named_date(self):
        source = inspect.cleandoc("""
            function stamp(h) { return h.Date; }
            console.log(stamp({}));
            if (Date.now() > 4102444800000) { while (true) {} }
            console.log('ran');
        """)
        self.assertNotIn('Date.now()', deobfuscate_source(source))


A_FUNCTION_REPLACING_ITS_ARGUMENTS = {
    'arguments replaced by an array of its elements': Program(
        a_program("""
            function main() {
              arguments = Array.prototype.slice.call(arguments);
              console.log(arguments.length);
            }
            main();
            """),
        prints('0'),
        Reading.COMMONJS,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFunctionReadingItsArgumentsIsNotInlined(TestBase):

    @backlog
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        row = A_FUNCTION_REPLACING_ITS_ARGUMENTS['arguments replaced by an array of its elements']
        self.assertEqual(row.read(), row.required())


A_BLOCK_FUNCTION_NAMED_ARGUMENTS_AFTER_A_READ_OF_THE_OBJECT = {
    'a mapped element read before a copy that never runs': Program(
        a_program("""
            function f(a, c) {
              a = 'x';
              var r = arguments[0];
              if (c) { function arguments() {} }
              return r;
            }
            console.log(f('orig', 0));
            """),
        prints('x'),
        Reading.COMMONJS,
    ),
    'the length of the object read before the copy': Program(
        a_program("""
            function main() {
              console.log(arguments.length);
              { function arguments() {} }
            }
            main();
            """),
        prints('0'),
        Reading.COMMONJS,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestTheObjectABlockFunctionNamedArgumentsReplacesIsReadBeforeTheCopy(TestBase):

    @wontfix('no program names a function it declares in a block arguments: strict code forbids the name, and no renamer picks it')
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        for label, row in A_BLOCK_FUNCTION_NAMED_ARGUMENTS_AFTER_A_READ_OF_THE_OBJECT.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestTheScriptValueOfAnUntakenBranchIsHeld(TestBase):
    """
    An `if` whose branch is not taken gives the script the value `undefined`, so
    `1; if (false) { 2; }` evaluates to `undefined` and not to `1`.
    """

    @backlog
    def test_the_script_ends_on_the_value_of_the_untaken_branch(self):
        source = '1;\nif (false) { 2; }\n'
        deobfuscated = deobfuscate_source(source, preserve_script_return=True)
        for evaluation in JsEvaluation:
            with self.subTest(evaluation=evaluation.value):
                self.assertEqual(
                    completion_values([deobfuscated], evaluation),
                    completion_values([source], evaluation),
                )


A_FRAME_OR_A_METHOD_REACHED_ONLY_AT_RUNTIME = {
    inspect.cleandoc("""
        Object.assign(Date.prototype.getTime, { call: function () { return 5000000000000; } });
        console.log(Date.prototype.getTime.call(new Date()) > 4102444800000);
    """): 'true\n',
    inspect.cleandoc("""
        function peek() { return this.callee.name; }
        function __p_impl(fn) { return arguments[0](); }
        function F() { return __p_impl(...arguments); }
        console.log(F(peek));
    """): '__p_impl\n',
    inspect.cleandoc("""
        function who() { return who[Buffer.from('Y2FsbGVy', 'base64').toString()].name; }
        function __p_impl(a) { return who() + a; }
        function F() { return __p_impl(...arguments); }
        console.log(F(1));
    """): '__p_impl1\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFrameOrAMethodReachedOnlyAtRuntime(TestBase):

    @wontfix(
        'no program gives getTime a call of its own, calls a function held in its arguments as a '
        'method of the object, or decodes the key caller at runtime: each is made up for the defect'
    )
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        rows = A_FRAME_OR_A_METHOD_REACHED_ONLY_AT_RUNTIME
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


#: The defaults of a generator and of an async generator run when it is called, not when it is first
#: resumed, so a default that throws makes the call itself throw.
A_DISCARDED_CALL_WHOSE_DEFAULT_THROWS = {
    inspect.cleandoc("""
        async function* g(a, x = 1 instanceof 2) { yield x; }
        try { g(1); console.log('created'); } catch (e) { console.log('call threw'); }
    """): 'call threw\n',
    inspect.cleandoc("""
        function* g(a, x = 1 instanceof 2) { yield x; }
        try { g(1); console.log('created'); } catch (e) { console.log('call threw'); }
    """): 'call threw\n',
    inspect.cleandoc("""
        function g(a, x = 1 instanceof 2) { return x; }
        try { g(1); console.log('created'); } catch (e) { console.log('call threw'); }
    """): 'call threw\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestADiscardedCallWhoseDefaultThrowsStillThrows(TestBase):

    @wontfix(
        'no program and no obfuscator writes a default that throws for operands made of literals; '
        'the shape is made up for the defect'
    )
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        rows = A_DISCARDED_CALL_WHOSE_DEFAULT_THROWS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


A_FLATTENED_READER_OF_A_BARE_NAME = inspect.cleandoc(
    """
    function reader() {
      function* gen(a, b, scope = {}, args) {
        while (a + b !== 100) {
          with (scope) {
            switch (a + b) {
              case 10:
                return done = true, label;
            }
          }
        }
      }
      var done;
      var result = gen(5, 5)["next"]()["value"];
      if (done) { return result; }
    }
    """
)

A_FLATTENED_WRITER_OF_THAT_NAME_ON_EVERY_OBJECT = inspect.cleandoc(
    """
    function writer() {
      function* gen(a, b, scope = {}, args) {
        while (a + b !== 100) {
          with (scope) {
            switch (a + b) {
              case 10:
                scope.proto = Object.prototype;
                scope.proto.label = "the label every object inherits";
                return done = true, 0;
            }
          }
        }
      }
      var done;
      var result = gen(5, 5)["next"]()["value"];
      if (done) { return result; }
    }
    """
)


#: Inside a `with` statement a bare name resolves to a property its object inherits before it
#: reaches the global, so once the writer has put `label` on `Object.prototype` the reader reads
#: that `label` and not the global one.
A_NAME_PUT_ON_EVERY_OBJECT_BY_A_LATER_FLATTENED_WRITER = {
    '\n'.join((
        'var label = "the global label";',
        A_FLATTENED_READER_OF_A_BARE_NAME,
        A_FLATTENED_WRITER_OF_THAT_NAME_ON_EVERY_OBJECT,
        'writer();',
        'console.log(reader());',
    )): 'the label every object inherits\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestANameAFlattenedWriterPutsOnEveryObjectStaysInheritedInTheReader(TestBase):

    @wontfix(
        'the obfuscator flattens the top level as well: a global the program declares becomes a slot '
        'the reader reads under a generated key, and a global it leaves bare is read inside the '
        'machine wrapping the whole program, whose recovery shows the write before the reader is '
        'decided; every obfuscation of this program by 2.0.0, 2.0.1 and 2.1.3 deobfuscates to one '
        'that prints what its input prints'
    )
    def test_a_reader_placed_before_the_writer_reads_the_inherited_name(self):
        rows = A_NAME_PUT_ON_EVERY_OBJECT_BY_A_LATER_FLATTENED_WRITER
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


A_MECHANISM_WRITTEN_THROUGH_A_SPELLING_OF_ITS_OWN = {
    'function C() {}\nC.prototype.q = 5;\n({}).__proto__.constructor = C;'
    '\nconsole.log(({}).constructor.prototype.q);':
        '5\n',
    'Object.defineProperty(({}).constructor.prototype, "__proto__", {value: 1});'
    '\n({}).__proto__.z = 9;\nconsole.log(({}).z);':
        'undefined\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAMechanismWrittenThroughASpellingIsStillWritten(TestBase):

    @wontfix(
        'no obfuscator and no program replaces the constructor or the __proto__ accessor every object '
        'inherits through a prototype it reaches from a literal'
    )
    def test_a_mechanism_written_through_a_spelling_is_still_written(self):
        rows = A_MECHANISM_WRITTEN_THROUGH_A_SPELLING_OF_ITS_OWN
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


#: Each program mapped to its text with the call of the `async` function answered. The first awaits
#: the call, and awaiting a promise differs from awaiting the value it resolves to only in how many
#: turns pass; the second discards the promise the call returns.
A_WRAPPING_THE_CALL_SITE_TAKES_BACK_OFF = {
    "async function w(a) { return 'b'; }\n"
    '(async function () { console.log(await w(2)); })();\n':
        "(async function() {\n  console.log(await 'b');\n})();",
    'function send(u) { return u; }\n'
    'async function get(u) { return send(u); }\n'
    "get('http://example.test/payload');\n":
        "'http://example.test/payload';",
}


class TestAWrappingTheCallSiteTakesBackOffIsStillInlined(TestBase):

    @opportunity
    def test_a_call_whose_wrapping_is_taken_off_is_answered(self):
        rows = A_WRAPPING_THE_CALL_SITE_TAKES_BACK_OFF
        self.assertEqual({source: folded(source) for source in rows}, rows)


class TestAStringArrayHolderNoLoopReadsIsStillResolved(TestBase):

    @wontfix('no obfuscator declares the function holding its string array async')
    def test_a_holder_the_rotation_never_reads_is_answered(self):
        """
        Node prints `3`: an `async` function runs its body up to its first `await` before it
        returns, so the first call of `A` already installs the plain function every later call
        reaches, and the loop breaks on its first pass without reading the promise that call
        answered.
        """
        self.assertEqual(
            "console.log('3');",
            folded(a_string_array_whose_rotation_runs('async function', target=3)),
        )


def _spelled_with_an_escaped_identifier(source: str) -> str:
    """
    *source* with each placeholder replaced by the unicode escape spelling the characters it names.

    The backslash is built with `chr(92)` because a tool rewriting this file may turn an escape
    written out in it into the characters it denotes, and the entry would then no longer ask about
    the escape; a result without a backslash is refused for the same reason.
    """
    result = source.replace('ESCAPED_IF', F'{chr(92)}u0069f')
    result = result.replace('ESCAPED_AIT', F'{chr(92)}u0061it')
    result = result.replace('ESCAPED_ET', F'{chr(92)}u0065t')
    if result != source and chr(92) not in result:
        raise AssertionError(F'the escape in {source!r} was flattened away')
    return result


#: Files that parse but break an early error rule, so an engine refuses each with a `SyntaxError`,
#: mapped to whether it is read as a module.
A_FILE_REFUSED_WITH_NOTHING_FABRICATED = {
    _spelled_with_an_escaped_identifier(source): module
    for source, module in (
        ('function ESCAPED_IF(){ return 1; } console.log(2);', False),
        ('let let = 1; console.log(2);', False),
        ('var o = { __proto__: null, __proto__: {} }; console.log(2);', False),
        ('var await = 1; console.log(2);', True),
        ('var awESCAPED_AIT = 1; console.log(2);', True),
    )
}


A_BINDING_PATTERN_NAMING_A_RESERVED_WORD = tuple(
    _spelled_with_an_escaped_identifier(source) for source in (
        'var { ESCAPED_IF } = { if: 7 }; console.log(1);',
        'var { ESCAPED_IF = 1 } = {}; console.log(1);',
        'function f({ ESCAPED_IF }){ return 1; } console.log(f({}));',
    )
)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFileRefusedWithNothingFabricatedIsNotAnsweredWithAProgram(TestBase):

    @wontfix(
        'every file here is one no engine loads, and no obfuscator or program that runs is written '
        'with a name escaping a reserved word, a let named let, two __proto__ keys or a module binding await'
    )
    def test_a_file_the_language_refuses_is_refused(self):
        rows = A_FILE_REFUSED_WITH_NOTHING_FABRICATED
        refused = ('', 'SyntaxError')
        self.assertEqual(
            {source: before_and_after(source, module=module) for source, module in rows.items()},
            {source: (refused, refused) for source in rows},
        )

    @wontfix(
        'a pattern binding a name whose escapes spell a reserved word is a file no engine loads, and no '
        'obfuscator or program writes one'
    )
    def test_a_pattern_binding_a_reserved_word_is_no_program(self):
        rows = A_BINDING_PATTERN_NAMING_A_RESERVED_WORD
        self.assertEqual(
            {source: well_formed(source) for source in rows},
            {source: False for source in rows},
        )


A_WITH_OBJECT_CARRYING_A_WRAPPER_NAME = {
    "var o = { W: function (a) { console.log('real', a); } };\n"
    'function W() { W = function () {}; }\n'
    'with (o) { W(1); }\n': 'real 1\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAWithObjectMayCarryTheNameAWrapperAnswersTo(TestBase):

    @wontfix(
        'the obfuscator calls its wrappers inside with bodies whose objects never carry the name of '
        'the wrapper, which would break its own program'
    )
    def test_a_call_the_scope_object_answers_is_left_standing(self):
        rows = A_WITH_OBJECT_CARRYING_A_WRAPPER_NAME
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_call_the_scope_object_does_not_answer_is_still_expanded(self):
        self.assertEqual(
            folded(
                'var o = { p: 1 };\n'
                'function W() { W = function () {}; }\n'
                'with (o) { W(console.log(1)); }\n'
                'console.log(2);\n'
            ),
            'var o = { p: 1 };\n'
            'with (o) {\n'
            '  console.log(1);\n'
            '}\n'
            'console.log(2);',
        )


A_WRAPPER_REBOUND_BY_AN_UNREADABLE_EVAL = {
    'function W() { W = function () {}; }\n'
    'eval(process.argv[9] || "W = function (a) { console.log(7, a); }");\n'
    'W(1);\n': '7 1\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnUnreadableEvalMayRebindAWrapper(TestBase):

    def test_node_prints_what_the_row_pins(self):
        rows = A_WRAPPER_REBOUND_BY_AN_UNREADABLE_EVAL
        self.assertEqual(
            {source: behavior(source) for source in rows},
            {source: (output, None) for source, output in rows.items()},
        )

    @wontfix('no program rebinds a self-disabling wrapper of the obfuscator from code it hands to eval')
    def test_a_call_after_the_eval_reaches_what_it_bound(self):
        rows = A_WRAPPER_REBOUND_BY_AN_UNREADABLE_EVAL
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


A_WITH_OBJECT_WATCHING_FOR_A_WRAPPER_NAME = {
    "var o = new Proxy({}, { has: function (t, k) { console.log('asked', k); return false; } });\n"
    'function W() { W = function () {}; }\n'
    'with (o) { W(console.log(1)); }\n'
    'console.log(2);\n': 'asked W\nasked console\n1\n2\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAWithObjectMayWatchForTheNameAWrapperAnswersTo(TestBase):

    @wontfix(
        'the obfuscator calls its wrappers inside with bodies over its own plain objects, never over '
        'a proxy that watches for the names looked up'
    )
    def test_the_question_the_expansion_takes_away_was_answered_by_code(self):
        rows = A_WITH_OBJECT_WATCHING_FOR_A_WRAPPER_NAME
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


A_WRAPPER_REBOUND_UNDER_AN_UNREADABLE_KEY = {
    'function W() { W = function () {}; }\n'
    "globalThis[process.argv[9] || 'W'] = function (a) { console.log('real', a); };\n"
    'W(1);\n': 'real 1\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnUnreadableKeyMayRebindAWrapperThroughTheGlobalObject(TestBase):

    def test_a_host_prints_what_the_row_pins(self):
        rows = A_WRAPPER_REBOUND_UNDER_AN_UNREADABLE_KEY
        self.assertEqual(
            {source: Reading.SCRIPT.behaves(source) for source in rows},
            {source: (output, None) for source, output in rows.items()},
        )

    @wontfix(
        'no program rebinds a self-disabling wrapper of the obfuscator through the global object under '
        'a key only its run supplies'
    )
    def test_a_call_after_the_write_reaches_what_it_bound(self):
        rows = A_WRAPPER_REBOUND_UNDER_AN_UNREADABLE_KEY
        self.assertEqual(
            {source: before_and_after_in_a_host(source) for source in rows},
            each_program_still_prints(rows),
        )


A_DIRECT_EVAL_IN_A_DEFAULT_DECLARING_A_NAME = as_classic_scripts(
    the_file_kind.A_DIRECT_EVAL_IN_A_DEFAULT_DECLARING_A_NAME
)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(
    A_DIRECT_EVAL_IN_A_DEFAULT_DECLARING_A_NAME,
    wontfix(
        'no program runs a direct eval in a parameter default that declares a var the function '
        'reads, a name it also declares outside the function'
    ),
)
class TestADirectEvalInADefaultDeclaresWhereItRuns(TestBase):
    pass


A_DIRECT_EVAL_IN_A_BODY_DECLARING_A_NAME = as_classic_scripts(
    the_file_kind.A_DIRECT_EVAL_IN_A_BODY_DECLARING_A_NAME
)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_DIRECT_EVAL_IN_A_BODY_DECLARING_A_NAME, todo)
class TestADirectEvalInABodyDeclaresWhereItRuns(TestBase):
    pass


A_VARIABLE_AN_UNREADABLE_EVAL_ASSIGNS_READ_BY_A_FUNCTION = as_classic_scripts({
    label: row
    for label, row in the_file_kind.A_VARIABLE_AN_UNREADABLE_EVAL_ASSIGNS_READ_BY_A_FUNCTION.items()
    if label != 'the long string of a slicing accessor'
})

A_LONG_STRING_AN_UNREADABLE_EVAL_REPLACES = as_classic_scripts({
    label: row
    for label, row in the_file_kind.A_VARIABLE_AN_UNREADABLE_EVAL_ASSIGNS_READ_BY_A_FUNCTION.items()
    if label == 'the long string of a slicing accessor'
})


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(
    A_LONG_STRING_AN_UNREADABLE_EVAL_REPLACES,
    wontfix('no program replaces the long string the obfuscator conceals its strings in from code it hands to eval'),
)
class TestALongStringAnUnreadableEvalMayReplaceIsNotWrittenIntoTheAccessor(TestBase):
    pass


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_VARIABLE_AN_UNREADABLE_EVAL_ASSIGNS_READ_BY_A_FUNCTION, todo)
class TestAVariableAnUnreadableEvalMayAssignIsNotWrittenIntoAFunctionReadingIt(TestBase):
    pass


A_NAME_THE_FILE_INSTALLS_ON_THE_GLOBAL_OBJECT = {
    'read through the installed name': Program(
        a_program("""
            globalThis.window = globalThis;
            var q = 1;
            console.log(window.q);
            """),
        prints('1'),
        Reading.SCRIPT,
    ),
    'a guard reads the installed name': Program(
        a_program("""
            globalThis.window = globalThis;
            var q = function (a) { console.log('q', a); };
            var w = window || {};
            w.q(1);
            """),
        prints('q 1'),
        Reading.SCRIPT,
    ),
    'a write through the installed name': Program(
        a_program("""
            globalThis.window = globalThis;
            var q = 1;
            window.q = 2;
            console.log(q);
            """),
        prints('2'),
        Reading.SCRIPT,
    ),
    'a name installed by assigning it undeclared': Program(
        a_program("""
            var q = 1;
            w = globalThis;
            w.q = 2;
            console.log(q);
            """),
        prints('2'),
        Reading.SCRIPT,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_NAME_THE_FILE_INSTALLS_ON_THE_GLOBAL_OBJECT, todo)
class TestANameTheFileInstallsOnTheGlobalObjectHoldsIt(TestBase):
    pass


A_GLOBAL_REACHED_INSIDE_A_CALL_THROUGH_A_NAME_HOLDING_THE_GLOBAL_OBJECT = {
    'a write inside a called function': Program(
        a_program("""
            var g = 1;
            var w = globalThis;
            function f() { w.g = 2; }
            f();
            console.log(g);
            """),
        prints('2'),
        Reading.SCRIPT,
    ),
    'a write inside a callback': Program(
        a_program("""
            var g = 1;
            var w = globalThis;
            [0].forEach(function () { w.g = 2; });
            console.log(g);
            """),
        prints('2'),
        Reading.SCRIPT,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_GLOBAL_REACHED_INSIDE_A_CALL_THROUGH_A_NAME_HOLDING_THE_GLOBAL_OBJECT, todo)
class TestAGlobalReachedInsideACallThroughANameHoldingTheGlobalObjectIsReachedThere(TestBase):
    pass


A_DECLARATION_ALSO_READ_THROUGH_THE_GLOBAL_OBJECT = {
    'a constant read through the object': Program(
        a_program("""
            var q = 1;
            console.log(globalThis.q);
            console.log(q);
            """),
        prints('1', '1'),
        Reading.SCRIPT,
    ),
    'a constant read through a name holding the object': Program(
        a_program("""
            var q = 1;
            var w = globalThis;
            console.log(w.q);
            console.log(q);
            """),
        prints('1', '1'),
        Reading.SCRIPT,
    ),
    'a namespace read through the object': Program(
        a_program("""
            var App = {};
            App.name = 'x';
            console.log(App.name);
            console.log(globalThis.App.name);
            """),
        prints('x', 'x'),
        Reading.SCRIPT,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_DECLARATION_ALSO_READ_THROUGH_THE_GLOBAL_OBJECT, todo)
class TestADeclarationAlsoReadThroughTheGlobalObjectIsKept(TestBase):
    pass


A_FUNCTION_CALLED_THROUGH_THE_GLOBAL_OBJECT = Program(
    a_program("""
        var counter = 0;
        function tick() { counter = counter + 1; }
        globalThis.tick();
        console.log(counter);
        """),
    prints('1'),
    Reading.SCRIPT,
)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFunctionCalledThroughTheGlobalObjectRuns(TestBase):

    @wontfix(
        'obfuscators route only names a program never declares through the global object, and '
        'a program calls its own functions by name'
    )
    def test_the_write_the_call_makes_is_seen(self):
        row = A_FUNCTION_CALLED_THROUGH_THE_GLOBAL_OBJECT
        self.assertEqual(row.read(), row.required())

    def test_the_program_prints_what_is_pinned(self):
        row = A_FUNCTION_CALLED_THROUGH_THE_GLOBAL_OBJECT
        self.assertEqual(row.behaves(), row.prints)


A_NAME_GIVEN_THE_GLOBAL_OBJECT_BY_A_HOST_TEST = {
    'a conditional chooses the spelling': Program(
        a_program("""
            var q = 1;
            var w = typeof window !== 'undefined' ? window : globalThis;
            w.q = 2;
            console.log(q);
            """),
        prints('2'),
        Reading.SCRIPT,
    ),
    'a test guards the spelling': Program(
        a_program("""
            var q = 1;
            var w = typeof globalThis === 'object' && globalThis || {};
            w.q = 2;
            console.log(q);
            """),
        prints('2'),
        Reading.SCRIPT,
    ),
    'a wrapper is handed the spelling a conditional chooses': Program(
        a_program("""
            var q = 1;
            (function (root) { root.q = 2; })(typeof self !== 'undefined' ? self : this);
            console.log(q);
            """),
        prints('2'),
        Reading.SCRIPT,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_NAME_GIVEN_THE_GLOBAL_OBJECT_BY_A_HOST_TEST, todo)
class TestANameGivenTheGlobalObjectByAHostTestHoldsIt(TestBase):
    pass


AN_INTRINSIC_PATCHED_THROUGH_A_CONDITIONAL_BASE = Program(
    a_program("""
        var c = Math.random() > 2;
        (c ? {} : Math).floor = function () { return 7; };
        console.log(Math.floor(1.5));
        """),
    prints('7'),
    Reading.SCRIPT,
)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnIntrinsicPatchedThroughAConditionalBaseIsSeen(TestBase):

    @wontfix(
        'a program patches a built-in through its own name or a name holding it, not through a '
        'conditional written in place of the object'
    )
    def test_the_patch_is_seen(self):
        row = AN_INTRINSIC_PATCHED_THROUGH_A_CONDITIONAL_BASE
        self.assertEqual(row.read(), row.required())

    def test_the_program_prints_what_is_pinned(self):
        row = AN_INTRINSIC_PATCHED_THROUGH_A_CONDITIONAL_BASE
        self.assertEqual(row.behaves(), row.prints)


THE_GLOBAL_OBJECT_A_CALL_SUPPLIES_HANDED_ON = {
    'a write through it': Program(
        a_program("""
            var q = 1;
            function a(g, k) { g[k] = 2; }
            function f() { a(this, 'q'); }
            f();
            console.log(q);
            """),
        prints('2'),
        Reading.SCRIPT,
    ),
    'a read through it': Program(
        a_program("""
            var q = 1;
            function a(g, k) { console.log(g[k]); }
            function f() { a(this, 'q'); }
            f();
            """),
        prints('1'),
        Reading.SCRIPT,
    ),
    'a name given it': Program(
        a_program("""
            var lib = 1;
            (function () {
              var root = this;
              function set() { root.lib = 2; }
              set();
            })();
            console.log(lib);
            """),
        prints('2'),
        Reading.SCRIPT,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(THE_GLOBAL_OBJECT_A_CALL_SUPPLIES_HANDED_ON, todo)
class TestAReceiverACallSuppliesMayBeHandedOn(TestBase):
    pass


class TestAnObjectPropertyFlagVariantIsStillRemoved(TestBase):

    @wontfix(
        'the obfuscator spells the run-once flag of its self-defending guard as a variable; the '
        'variant with an object property is written by hand and no witnessed emission spells it'
    )
    def test_the_object_property_flag_guard_is_removed(self):
        source = a_program("""
            var a = function () {
              var s = { b: true };
              return function (c, d) {
                var e = s.b ? function () {
                  if (d) { var f = d.apply(c, arguments); return d = null, f; }
                } : function () {};
                return s.b = false, e;
              };
            }();
            a(this, function () { console.log = function () {}; })();
            console.log('done');
            """)
        self.assertEqual("console.log('done');", deobfuscate_source(source))


A_CONVERSION_WITH_AN_EFFECT_THE_SCAN_CANNOT_SEE = {
    'X = 5;\n'
    "var o = { toString: function () { delete globalThis.X; return ''; } };\n"
    "var s = '' + o;\nX;\nconsole.log('end');\n": ('', 'ReferenceError'),

    'X = 5;\n'
    'var o = { valueOf: function () { delete globalThis.X; return 1; } };\n'
    "var n = o + 1;\nX;\nconsole.log('end');\n": ('', 'ReferenceError'),

    "var o = { toString: function () { globalThis.Q = 1; return ''; } };\n"
    "var s = '' + o;\nconsole.log(typeof globalThis.Q);\n": ('number\n', None),

    'X = 5;\n'
    "var o = { toString: function () { delete globalThis.X; return 'o'; } };\n"
    "var s = '' + o;\nX;\nconsole.log(s);\n": ('', 'ReferenceError'),

    'X = 5;\n'
    "var o = { toString: function () { delete globalThis.X; return 'o'; } };\n"
    'var s = `${o}`;\nX;\nconsole.log(s);\n': ('', 'ReferenceError'),

    'X = 5;\n'
    'var o = { valueOf: function () { delete globalThis.X; return 7; } };\n'
    'var s = o < 8;\nX;\nconsole.log(s);\n': ('', 'ReferenceError'),

    'function f(o) {\n'
    '  var log = [];\n'
    '  o.log = log;\n'
    "  var a = o + 1, b = (log.push('b'), 0), c = a;\n"
    "  return log.join('') + c;\n"
    '}\n'
    "console.log(f({ valueOf: function () { this.log.push('v'); return 1; } }));\n": ('vb2\n', None),

    'function f(o) {\n'
    '  var log = [];\n'
    '  o.log = log;\n'
    '  var a = o + 1;\n'
    "  var b = (log.push('b'), 0);\n"
    '  var c = a;\n'
    "  return log.join('') + c;\n"
    '}\n'
    "console.log(f({ valueOf: function () { this.log.push('v'); return 1; } }));\n": ('vb2\n', None),

    'function f() {\n'
    '  var x;\n'
    "  var o = { toString: function () { x = 5; return 'o'; } };\n"
    "  var s = '' + o;\n"
    '  x = undefined;\n'
    '  return [s, x];\n'
    '}\n'
    'console.log(f());\n': ("[ 'o', undefined ]\n", None),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAConversionWithAnEffectIsNeitherDroppedNorMoved(TestBase):

    @backlog
    def test_each_program_still_observes_its_conversions_effect(self):
        rows = A_CONVERSION_WITH_AN_EFFECT_THE_SCAN_CANNOT_SEE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            {source: (answer, answer) for source, answer in rows.items()},
        )


A_RELOCATED_MAY_THROW_READ_KEEPS_ITS_ORDER = {
    'try {\n'
    '  console.log(function (a, b) { return b() + a; }(zzz, function () {\n'
    '    console.log(1);\n'
    '    return 2;\n'
    '  }));\n'
    "} catch (e) { console.log('caught'); }\n": ('caught\n', None),
    'var o = { q: zzz };\n'
    'console.log(1);\n'
    'console.log(o.q);\n': ('', 'ReferenceError'),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestARelocatedMayThrowReadIsReorderedPastAnEffect(TestBase):

    @backlog
    def test_a_relocated_may_throw_read_keeps_its_order(self):
        rows = A_RELOCATED_MAY_THROW_READ_KEEPS_ITS_ORDER
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            {source: (behavior, behavior) for source, behavior in rows.items()},
        )


class TestACommentBehindTheLastStatementOfALiftedBlockIsKept(TestBase):

    @backlog
    def test_the_comment_survives_the_fold_that_lifts_the_block(self):
        output = deobfuscate_source('if (true) { console.log(1); /* c */ } console.log(2);')
        self.assertEqual(('if' in output, '/* c */' in output), (False, True))


class TestAClassHeritageTheFileRefusesEndsWhereTheStatementDoes(TestBase):
    """
    Node refuses the source at `g`: the object literal is the heritage of the class, so the class
    body is missing, and `g = 1;` is a statement of its own.
    """

    @backlog
    def test_the_assignment_behind_the_refused_class_is_read_as_a_statement(self):
        source = 'class C extends { m(){} } g = 1;'
        tree = JsParser(source).parse()
        self.assertEqual(
            (unread_spans(tree), len(tree.body)),
            (['class C extends { m(){} }'], 2),
        )


class TestARestElementOffTheGlobalObjectIsNotAReflectionSurface(TestBase):

    @backlog
    def test_a_rest_capture_of_the_global_object_keeps_a_dependent_guard(self):
        source = inspect.cleandoc(
            """
            var a = ['x'];
            const { ...r } = globalThis;
            r[k](payload);
            if (!a) {
              X();
            } else {
              Y();
            }
            """
        )
        self.assertEqual(source, deobfuscate_source(source))


#: The constructor of `[].constructor` is `Function`, so the code runs, and it replaces
#: `Array.prototype.join`, which converting `[5]` to a number calls.
CODE_RUN_THROUGH_A_CONSTRUCTOR_READ_IN_PLACE = {
    inspect.cleandoc("""
        var code = process.argv.length > 99 ? '' : 'Array.prototype.join = function () { return "J"; };';
        [].constructor.constructor(code)();
        console.log(-[5]);
    """): 'NaN\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestCodeRunThroughAConstructorReadInPlaceIsAReflectionSurface(TestBase):

    @backlog
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        rows = CODE_RUN_THROUGH_A_CONSTRUCTOR_READ_IN_PLACE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestPreserveScriptReturnDoesNotHoldASelfDefendingGuardCompletion(TestBase):

    _DEFENSE_CODE = (
        'var a = (function() {'
        '  var b = true;'
        '  return function(c, d) {'
        '    var e = b ? function() {'
        '      if (d) { var f = d.apply(c, arguments); return d = null, f; }'
        '    } : function() {};'
        '    return b = false, e;'
        '  };'
        '}()), g = a(this, function() {'
        "  return g.toString().search('(((.+)+)+)+$')"
        "    .toString().constructor(g).search('(((.+)+)+)+$');"
        '});'
    )

    @wontfix(
        'a self-defending guard is armed for its effect, and no real payload ends on a call of it '
        'read for its value'
    )
    def test_it_holds_a_self_defending_guard_call_at_the_completion(self):
        source = self._DEFENSE_CODE + 'g();'
        deobfuscated = deobfuscate_source(source, preserve_script_return=True)
        for evaluation in JsEvaluation:
            with self.subTest(evaluation=evaluation.value):
                self.assertEqual(
                    completion_values([deobfuscated], evaluation),
                    completion_values([source], evaluation),
                    F'preserve_script_return changed the completion; result was:'
                    F'{chr(10)}{deobfuscated}',
                )


A_PACKED_ACCESS_A_WITH_OBJECT_SUPPLIES = {
    'read': Program(
        'var z = { x: 42 };\n'
        'var x = 7;\n'
        "Function('o', 'with(z){ console.log(o.a); }')({ get 'a'() { return x; } });\n",
        prints('7'),
        Reading.SCRIPT,
    ),
    'write': Program(
        'var z = { x: 42 };\n'
        'var x = 7;\n'
        "Function('o', 'with(z){ o.a = 9; }')({ set 'a'(v) { x = v; } });\n"
        'console.log(x, z.x);\n',
        prints('9 42'),
        Reading.SCRIPT,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_PACKED_ACCESS_A_WITH_OBJECT_SUPPLIES, backlog)
class TestAPackedAccessAWithObjectSuppliesStillGoesThroughTheProxy(TestBase):
    pass


class TestAHandlerTheListedHostsDoNotCallIsKept(TestBase):

    @todo
    def test_a_fetch_handler_of_a_service_worker_is_kept_without_a_pin(self):
        source = a_program("""
            onfetch = function (event) { console.log(event.request.url); };
            """)
        self.assertIn('event.request.url', folded(source))

    @todo
    def test_a_connect_handler_of_a_shared_worker_is_kept_without_a_pin(self):
        source = a_program("""
            onconnect = function (event) { console.log(event.ports.length); };
            """)
        self.assertIn('event.ports.length', folded(source))

    @todo
    def test_a_touch_handler_stored_on_the_window_is_kept_for_a_browser(self):
        source = a_program("""
            window.ontouchstart = function (event) { console.log(event.touches.length); };
            """)
        self.assertIn('event.touches.length', folded(source, environment=HostEnvironment.browser))


A_KEY_WRITTEN_WHERE_THE_IN_FOLD_DOES_NOT_LOOK = {
    a_program("""
        function t() { var X = {}; var Y = X; Y.k = 1; return 'k' in X; }
        console.log(t());
        """): 'true\n',
    a_program("""
        function t() { var X = {}; [X.k] = [1]; return 'k' in X; }
        console.log(t());
        """): 'true\n',
    a_program("""
        function t() { var X = {}; for (X.k in {p: 1}); return 'k' in X; }
        console.log(t());
        """): 'true\n',
    a_program("""
        function t() { var X = {}; X.__defineGetter__('k', function () { return 1; }); return 'k' in X; }
        console.log(t());
        """): 'true\n',
    a_program("""
        function t() { var X = {}; X.valueOf().k = 1; return 'k' in X; }
        console.log(t());
        """): 'true\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAKeyWrittenThroughAnotherFormIsInTheObject(TestBase):

    @wontfix(
        'obfuscated files ask with in only for keys written straight into a literal, and a '
        'program writing the key another way first is made up for the defect'
    )
    def test_the_key_is_found(self):
        rows = A_KEY_WRITTEN_WHERE_THE_IN_FOLD_DOES_NOT_LOOK
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


A_BUILT_IN_KEY_ASKED_OF_AN_OBJECT_WITHOUT_A_PROTOTYPE = {
    a_program("""
        function t() { var X = {}; var Y = X; Y.__proto__ = null; return 'hasOwnProperty' in X; }
        console.log(t());
        """): 'false\n',
    a_program("""
        function t() { var X = {}; Object.setPrototypeOf(X, null); return 'hasOwnProperty' in X; }
        console.log(t());
        """): 'false\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestABuiltInKeyIsMissingFromAnObjectWithoutAPrototype(TestBase):

    @wontfix(
        'no obfuscated file clears a prototype (none of 2,074 checked), and asking an object whose '
        'prototype a program cleared for an inherited key is made up for the defect'
    )
    def test_the_key_is_missing(self):
        rows = A_BUILT_IN_KEY_ASKED_OF_AN_OBJECT_WITHOUT_A_PROTOTYPE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


A_FUNCTION_WITHOUT_A_PROTOTYPE_PROPERTY = {
    a_program("""
        function t() { const X = () => {}; return 'prototype' in X; }
        console.log(t());
        """): 'false\n',
    a_program("""
        function t() { const X = async function () {}; return 'prototype' in X; }
        console.log(t());
        """): 'false\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnArrowOrAsyncFunctionHasNoPrototypeProperty(TestBase):

    @wontfix(
        'no obfuscated file asks a function for prototype with in (none of 2,074 checked), and a '
        'program asking an arrow or async function literal is made up for the defect'
    )
    def test_the_property_is_missing(self):
        rows = A_FUNCTION_WITHOUT_A_PROTOTYPE_PROPERTY
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


AN_OBJECT_PROTOTYPE_WRITTEN_INDIRECTLY = {
    a_program("""
        Object.assign(Object.prototype, {k: 1});
        function t() { var X = {}; return 'k' in X; }
        console.log(t());
        """): 'true\n',
    a_program("""
        Reflect.set(Object.prototype, 'k', 1);
        function t() { var X = {}; return 'k' in X; }
        console.log(t());
        """): 'true\n',
}

A_GETTER_INSTALLED_THROUGH_A_PARAMETER = a_program("""
    var P = Object.prototype;
    function install(o) { o.__defineGetter__('k', function () { return this.g(); }); }
    install(P);
    var NS = {h: 1};
    NS.g = function () { return a[0]; };
    console.log(NS.k);
    const a = [7, 8];
    """)

A_GETTER_INSTALLED_THROUGH_ANOTHER_OBJECT = {
    start: Program(
        a_program(F"""
            var NS = {{h: 1}};
            NS.g = function () {{ return a[0]; }};
            var other = {{}};
            {path}.__defineGetter__('k', function () {{ return this.g(); }});
            console.log(NS.k);
            const a = [7, 8];
            """),
        ('', 'ReferenceError'),
    )
    for start, path in {
        'the prototype of another object': 'other.__proto__',
        'the constructor of another object': 'other.constructor.prototype',
        'the prototype of the prototype of an array': '[].__proto__.__proto__',
    }.items()
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnIndirectWriteToObjectPrototypeIsSeen(TestBase):

    @wontfix(
        'no obfuscated file writes to Object.prototype (none of 2,074 checked), and a program '
        'asking a fresh literal for a key it put there by Object.assign is made up for the defect'
    )
    def test_the_key_is_found(self):
        rows = AN_OBJECT_PROTOTYPE_WRITTEN_INDIRECTLY
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    @wontfix(
        'no obfuscated file writes to Object.prototype (none of 2,074 checked), and a getter '
        'there that calls a method of whatever object reads it is made up for the defect'
    )
    def test_a_getter_installed_through_a_parameter_still_throws(self):
        self.assertEqual(
            before_and_after(A_GETTER_INSTALLED_THROUGH_A_PARAMETER),
            (('', 'ReferenceError'), ('', 'ReferenceError')),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAGetterInstalledThroughAnotherObjectIsSeen(TestBase):

    @wontfix(
        'no obfuscated file writes to Object.prototype (none of 2,074 checked), and a getter '
        'there that calls a method of whatever object reads it is made up for the defect'
    )
    def test_the_getter_still_throws(self):
        rows = A_GETTER_INSTALLED_THROUGH_ANOTHER_OBJECT
        self.assertEqual(
            {label: row.read() for label, row in rows.items()},
            {label: row.required() for label, row in rows.items()},
        )


AN_OBJECT_A_BUILT_IN_METHOD_MUTATES = {
    a_program("""
        function t() { var X = {a: 1}; X.valueOf().a = 2; return X.a; }
        console.log(t());
        """): '2\n',
    a_program("""
        function t() { var o = {k: 1}; o.__defineGetter__('k', function () { return 2; }); return o.k; }
        console.log(t());
        """): '2\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestABuiltInMethodCalledOnAnObjectMayChangeIt(TestBase):

    @wontfix(
        'no obfuscated file calls valueOf or __defineGetter__ (none of 2,074 checked), and a '
        'program changing its own lookup table that way is made up for the defect'
    )
    def test_the_property_is_read_after_the_change(self):
        rows = AN_OBJECT_A_BUILT_IN_METHOD_MUTATES
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


AN_INTRINSIC_HELD_WHERE_THE_MODELS_DO_NOT_FOLLOW_IT = {
    a_program("""
        [Object][0].prototype.k = 1;
        var B = {x: 1};
        console.log(B.k);
        """): '1\n',
    a_program("""
        try { throw Object; } catch (e) { e.prototype.k = 1; }
        var B = {x: 1};
        console.log(B.k);
        """): '1\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnIntrinsicWrittenThroughAnElementOrAThrownValueIsSeen(TestBase):

    @wontfix(
        'a program writes a prototype through the name of its constructor, not through an array '
        'element or a thrown value holding the constructor'
    )
    def test_the_key_is_found(self):
        rows = AN_INTRINSIC_HELD_WHERE_THE_MODELS_DO_NOT_FOLLOW_IT
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


THE_GLOBAL_OBJECT_HELD_WHERE_THE_MODELS_DO_NOT_FOLLOW_IT = {
    a_program("""
        var C = {x: 1};
        var o = {w: globalThis};
        o.z = 0;
        o.w.C = {x: 5};
        console.log(C.x);
        """): '5\n',
    a_program("""
        var C = {x: 1};
        function f(w = globalThis) { w.C = {x: 5}; }
        f();
        console.log(C.x);
        """): '5\n',
    a_program("""
        var C = {x: 1};
        var [w] = [globalThis];
        w.C = {x: 5};
        console.log(C.x);
        """): '5\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestTheGlobalObjectInAPropertyADefaultOrAPatternIsWrittenThrough(TestBase):

    @wontfix(
        'a program names the global object with a variable or hands it to a parameter, not through '
        'an object property, a default parameter or a destructuring'
    )
    def test_the_write_is_seen(self):
        rows = THE_GLOBAL_OBJECT_HELD_WHERE_THE_MODELS_DO_NOT_FOLLOW_IT
        self.assertEqual(
            {source: before_and_after_in_a_host(source) for source in rows},
            each_program_still_prints(rows),
        )


AN_OBJECT_READ_THROUGH_THE_GLOBAL_OBJECT_WITH_ITS_OWN_VALUE = {
    a_program("""
        var A = {k: "A", n: 1};
        console.log(globalThis[A.k].n);
        """): '1\n',
    a_program("""
        var A = {k: globalThis, n: 1};
        var w = A.k;
        console.log(w.A.n);
        """): '1\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnObjectReadThroughTheGlobalObjectWithItsOwnValueIsKept(TestBase):

    @wontfix(
        'a storage object holds neither its own name nor the global object it is then read '
        'through, and a program reading it that way is made up for the defect'
    )
    def test_the_object_is_still_read(self):
        rows = AN_OBJECT_READ_THROUGH_THE_GLOBAL_OBJECT_WITH_ITS_OWN_VALUE
        self.assertEqual(
            {source: before_and_after_in_a_host(source) for source in rows},
            each_program_still_prints(rows),
        )


A_GLOBAL_REWRITTEN_UNDER_A_KEY_OF_THE_OBJECT_HOLDING_ITS_VALUE = a_program("""
    var x = 1;
    function main() { var A = {k: "x", v: x}; globalThis[A.k] = 2; return A.v; }
    console.log(main());
    """)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAValueAnObjectHoldsIsReadWhereTheLiteralReadIt(TestBase):

    @wontfix(
        'a storage object holds strings and helper functions, not the value of a global it also '
        'names as a key that the program then writes under'
    )
    def test_the_value_is_the_one_the_literal_read(self):
        self.assertEqual(
            before_and_after_in_a_host(A_GLOBAL_REWRITTEN_UNDER_A_KEY_OF_THE_OBJECT_HOLDING_ITS_VALUE),
            (('1\n', None), ('1\n', None)),
        )


AN_ARROW_READING_NEW_TARGET_CALLED_FROM_A_NESTED_FUNCTION = a_program("""
    function g() {
      var A = {f: () => new.target};
      function h() { return A.f(); }
      console.log(h() === g);
    }
    new g();
    """)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnArrowReadingNewTargetReadsTheFunctionItWasWrittenIn(TestBase):

    @wontfix(
        'no obfuscator stores an arrow function reading new.target in an object, and a program '
        'calling one from another function is made up for the defect'
    )
    def test_the_arrow_reads_its_own_new_target(self):
        self.assertEqual(
            before_and_after(AN_ARROW_READING_NEW_TARGET_CALLED_FROM_A_NESTED_FUNCTION),
            (('true\n', None), ('true\n', None)),
        )


A_GETTER_ONE_CALL_INSTALLS_READ_IN_AN_ARGUMENT_ANOTHER_DROPS = a_program("""
    var O = {id: function (x) { return x; }, drop: function (a) { return 1; }};
    function h() { return ({}).q; }
    function later() { return O.drop(h()); }
    Object[O.id("defineProperty")](Object.prototype, "q", {get: function () { console.log("side"); return 1; }});
    console.log(later());
    """)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestACallOfAnObjectSeesWhatAnEarlierCallOfItShowed(TestBase):

    @wontfix(
        'storage objects hold no identity wrapper whose answer names an installer, and a getter '
        'on every object read by an argument a wrapper drops is made up for the defect'
    )
    def test_the_getter_still_runs(self):
        self.assertEqual(
            before_and_after(A_GETTER_ONE_CALL_INSTALLS_READ_IN_AN_ARGUMENT_ANOTHER_DROPS),
            (('side\n1\n', None), ('side\n1\n', None)),
        )


A_COPY_IN_A_WITH_BODY_READING_A_NAME_THROUGH_A_GETTER = a_program("""
    var obj = {};
    Object.defineProperty(obj, "Math", {get: function () { console.log("got"); return Math; }});
    with (obj) {
      (function () {
        var O = {k: "call", g: function (b) { return b; }, f: function (k, a) { return k; }};
        console.log(O.f(""[O.k], O.g(Math)));
      })();
    }
    """)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAReadOfACopyInAWithBodyRunsItsGetter(TestBase):

    @wontfix(
        'obfuscated storage objects are not folded inside a with body whose object carries getters '
        'for the names their wrappers are handed'
    )
    def test_the_getter_still_runs(self):
        self.assertEqual(
            before_and_after(A_COPY_IN_A_WITH_BODY_READING_A_NAME_THROUGH_A_GETTER),
            (('got\nundefined\n', None), ('got\nundefined\n', None)),
        )


AN_OBJECT_REPLACED_THROUGH_THE_GLOBAL_OBJECT_UNDER_A_RUNTIME_KEY = a_program("""
    var K = "C";
    var C = {x: 1};
    globalThis[K] = {x: 5};
    console.log(C.x);
    """)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnObjectReplacedThroughTheGlobalObjectUnderARuntimeKeyIsRead(TestBase):

    @wontfix(
        'a program replacing its own top-level object through the global object under a key it '
        'computes is made up for the defect'
    )
    def test_the_replaced_object_is_read(self):
        self.assertEqual(
            before_and_after_in_a_host(AN_OBJECT_REPLACED_THROUGH_THE_GLOBAL_OBJECT_UNDER_A_RUNTIME_KEY),
            (('5\n', None), ('5\n', None)),
        )


AN_OBJECT_NAMING_A_KEY_TWICE_WITH_A_THROWING_VALUE_FIRST = a_program("""
    function f() { var O = {a: x, a: 2}; return O.a; }
    try { console.log(f()); } catch (e) { console.log(e.name); }
    """)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnEarlierValueOfAKeyNamedTwiceStillThrows(TestBase):

    @wontfix(
        'obfuscators emit every key of a storage object once, and a literal naming a key twice is '
        'made up for the defect'
    )
    def test_the_literal_still_throws(self):
        self.assertEqual(
            before_and_after(AN_OBJECT_NAMING_A_KEY_TWICE_WITH_A_THROWING_VALUE_FIRST),
            (('ReferenceError\n', None), ('ReferenceError\n', None)),
        )


A_PARAMETER_NAMED_EVAL_CALLED_IN_AN_INLINED_FUNCTION = a_program("""
    var O = {f: function (eval, s) { return eval(s); }};
    function main() { O.f(eval, "var x = 1"); return typeof x; }
    console.log(main());
    """)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAParameterNamedEvalRunsTheCodeInTheScopeOfItsFunction(TestBase):
    """
    A call through a name spelled `eval` that holds the built-in `eval` is a direct `eval`, whatever
    binds the name, so `var x` declares a variable of `O.f` and `main` finds no `x`.
    """

    def test_a_host_prints_undefined_for_the_program(self):
        self.assertEqual(
            Reading.SCRIPT.behaves(A_PARAMETER_NAMED_EVAL_CALLED_IN_AN_INLINED_FUNCTION),
            prints('undefined'),
        )

    @wontfix(
        'no obfuscator names a parameter eval, and a program handing eval to a function whose '
        'parameter has that name is made up for the defect'
    )
    def test_the_code_runs_in_the_scope_of_the_function_holding_the_parameter(self):
        self.assertEqual(
            before_and_after_in_a_host(A_PARAMETER_NAMED_EVAL_CALLED_IN_AN_INLINED_FUNCTION),
            (('undefined\n', None), ('undefined\n', None)),
        )


AN_INSTALLER_TAKEN_BY_DESTRUCTURING = {
    a_program("""
        var {defineProperty: d} = Object;
        d(Object.prototype, "q", {value: 1});
        var B = {y: 1};
        console.log(B.q);
        """): '1\n',
    a_program("""
        var {["defineProperty"]: d} = Object;
        d(Object.prototype, "q", {value: 1});
        var B = {y: 1};
        console.log(B.q);
        """): '1\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnInstallerTakenByDestructuringIsSeen(TestBase):

    @backlog
    def test_the_install_is_seen(self):
        rows = AN_INSTALLER_TAKEN_BY_DESTRUCTURING
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


A_NAMESPACE_AN_UNREADABLE_EVAL_CHANGES = as_classic_scripts(
    the_file_kind.A_NAMESPACE_AN_UNREADABLE_EVAL_CHANGES
)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_NAMESPACE_AN_UNREADABLE_EVAL_CHANGES, todo)
class TestANamespaceAnUnreadableEvalReachesStaysWhole(TestBase):
    pass


A_RECURSIVE_FUNCTION_CALLED_THROUGH_THE_GLOBAL_OBJECT_UNDER_ANOTHER_NAME = Program(
    a_program("""
        function f(n) { return n > 0 ? f(n - 1) : c; }
        var w = (function () { return this; })();
        console.log(w.f(1));
        var c;
        c = 1;
        """),
    prints('undefined'),
    Reading.SCRIPT,
)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestARecursiveFunctionCalledThroughTheGlobalObjectReadsTheValueUnset(TestBase):

    @wontfix(
        'obfuscators route only names a program never declares through the global object, and '
        'a program calls its own functions by name'
    )
    def test_the_value_is_read_unset(self):
        row = A_RECURSIVE_FUNCTION_CALLED_THROUGH_THE_GLOBAL_OBJECT_UNDER_ANOTHER_NAME
        self.assertEqual(row.read(), row.required())


class TestAValueNameWrittenThroughTheThisOfAFunctionStopsTheFold(TestBase):
    """
    JScript lets a program write `undefined`, and a function called bare runs with the global object
    as `this`, so `this.undefined = 5` changes `undefined` for the whole script, and neither `u` nor
    `typeof undefined` may be folded.
    """

    @wontfix(
        'no obfuscated file writes undefined (none of 2,074 checked), and a program writing it '
        'through the this of a function is made up for the defect'
    )
    def test_the_name_stays(self):
        output = deobfuscate_source(a_program("""
            (function () { this.undefined = 5; })();
            var u = undefined;
            WScript.Echo(u);
            WScript.Echo(u);
            WScript.Echo(typeof undefined);
            """))
        self.assertEqual(
            (output.count('void 0'), output.count('typeof undefined')),
            (0, 1),
        )


class TestAValueNameWrittenThroughAnAliasOfTheGlobalObjectStopsTheFold(TestBase):
    """
    JScript lets a program write `undefined`, so each write through an alias of the global object
    changes what `undefined + 1` reads, and the sum may not be folded.
    """

    @wontfix(
        'no obfuscated file writes undefined (see the entry for a write through the this of a '
        'function), and a program writing it through an alias of the global object is made up for '
        'the defect'
    )
    def test_the_name_stays(self):
        for source in [
            'var g = this;\ng.undefined = 7;\nWScript.Echo(undefined + 1);',
            'function self() { return this; }\nself().undefined = 7;\nWScript.Echo(undefined + 1);',
            'with (this) { undefined = 7; }\nWScript.Echo(undefined + 1);',
        ]:
            with self.subTest(source=source):
                self.assertIn('undefined + 1', deobfuscate_source(source))


A_GLOBAL_AN_IMPORTER_IN_A_CYCLE_READS_BEFORE_IT_EXISTS = (
    a_program("""
        import { g } from './b.mjs';
        export function f() { x; return 1; }
        globalThis.x = 1;
        console.log(f());
        g();
        """),
    a_program("""
        import { f } from './main.mjs';
        export function g() {}
        console.log(f());
        """),
)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAGlobalAnImporterInACycleReadsEarlyMayNotExistYet(TestBase):

    @wontfix(
        'no obfuscated file holds an import or export (none of 2,074 checked), and an import '
        'cycle creating a global after the other module read it is made up for the defect'
    )
    def test_the_global_is_read_before_it_exists(self):
        exporter, importer = A_GLOBAL_AN_IMPORTER_IN_A_CYCLE_READS_BEFORE_IT_EXISTS
        rewritten = deobfuscate_source(exporter, execution=ExecutionModel.module)
        self.assertEqual(
            (
                module_graph_behavior({'main.mjs': exporter, 'b.mjs': importer}, 'main.mjs'),
                module_graph_behavior({'main.mjs': rewritten, 'b.mjs': importer}, 'main.mjs'),
            ),
            (('', 'ReferenceError'), ('', 'ReferenceError')),
        )


A_CONSTANT_DEFINED_BEFORE_THE_HOST_GETS_CONTROL = a_program("""
    const K = ['x'];
    function onload() { console.log(K[0]); }
    fire();
    """)


class TestAConstantDefinedBeforeTheHostGetsControlIsFoldedIntoAnEntryPoint(TestBase):
    """
    A host calls a declared entry point only while it holds control: during a call into code outside
    the file, such as `fire`, or once the script has finished. `K` is defined before either, so
    every call of `onload` reads it.
    """

    @opportunity
    def test_the_constant_is_folded(self):
        output = deobfuscate_source(
            A_CONSTANT_DEFINED_BEFORE_THE_HOST_GETS_CONTROL,
            entrypoints=('onload',),
        )
        self.assertEqual(
            ('function onload' in output, 'K[0]' in output),
            (True, False),
        )


#: The initializer of a `var` inside a `with` body assigns the property of the same name on the
#: object, so the `var` keeps `undefined`.
A_VAR_INITIALIZED_INSIDE_A_WITH_BODY = {
    'a scalar read by a function': Program(
        a_program("""
            var obj = { T: 1 };
            with (obj) { var T = 'x'; }
            function A() { return T + '!'; }
            console.log(A());
            """),
        prints('undefined!'),
    ),
    'a string read in its own scope and by a function': Program(
        a_program("""
            var o = { x: "from o" };
            with (o) { var x = "declared"; }
            function f() { return x; }
            console.log(typeof x, f());
            """),
        prints('undefined undefined'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_VAR_INITIALIZED_INSIDE_A_WITH_BODY, todo)
class TestAVarInitializedInsideAWithBodyMayWriteTheObject(TestBase):
    pass


A_GLOBAL_WRITTEN_THROUGH_A_FOUND_GLOBAL_OBJECT = {
    'a scalar read by a function': Program(
        a_program("""
            function A(i) { return K + i; }
            var K = 'x';
            var g = Function('return this')();
            g.K = 'y';
            console.log(A(0));
            """),
        prints('y0'),
        Reading.SCRIPT,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_GLOBAL_WRITTEN_THROUGH_A_FOUND_GLOBAL_OBJECT, todo)
class TestAGlobalWrittenThroughAFoundGlobalObjectChangesTheVariable(TestBase):
    pass


#: Under Annex B a `var` inside a `catch` clause may share the name of the clause's parameter; its
#: initializer then writes the parameter, and the `var` keeps `undefined`.
A_VAR_NAMED_LIKE_ITS_CATCH_PARAMETER = {
    a_program("""
        try { throw 0; } catch (T) { var T = 'x'; }
        console.log(T);
        """): 'undefined\n',
    a_program("""
        function A(i) { return T[i]; }
        try { throw 0; } catch (T) { var T = ['x', 'y']; }
        try { console.log(A(0)); } catch (e) { console.log(e.name); }
        """): 'TypeError\n',
}


class TestAVarNamedLikeItsCatchParameterKeepsUndefined(TestBase):

    @wontfix(
        'no obfuscated file declares a var under the name of the catch parameter around it (none '
        'of 2,074 checked), and such a declaration is made up for the defect'
    )
    def test_the_var_keeps_undefined(self):
        rows = A_VAR_NAMED_LIKE_ITS_CATCH_PARAMETER
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


A_CLOSURE_A_NESTED_RUN_REPLACED = {
    a_program("""
        var h;
        function S() { return h(); }
        function Q(n) {
          h = function () { return T; };
          if (!n) return 'early';
          Q(0);
          var T = 'x';
          return S();
        }
        console.log(Q(1));
        """): 'undefined\n',
}


class TestAClosureANestedRunReplacedReadsThatRun(TestBase):

    @wontfix(
        'a recursive function replacing a shared closure on every run and calling it after a '
        'nested run is made up for the defect; no obfuscator writes that shape'
    )
    def test_the_closure_reads_its_own_run(self):
        rows = A_CLOSURE_A_NESTED_RUN_REPLACED
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


A_SELF_CHECK_TRIPPED_THROUGH_A_MADE_UP_ROUTE = {
    r'(function () {}).__proto__.toString = function () { return "\n"; };' '\n' + checked():
        'tampered\nran\n',
    checked_by_name(
        F'function g() {{ var k = ["cal", "ler"].join(process.argv[9] || ""); g[k].toString = {SET_A_LINE_BREAK}; }} ',
        'g(); ',
    ):
        'tampered\n',
    (
        'var NS = {};\nNS.g = function () {\n};\n'
        r'var T = function () { const R = new RegExp("\n"); return R.test(NS.g); };' '\n'
        'if (T()) { console.log("tampered"); } else { console.log("clean"); }\n'
        'NS.g();\n'
    ):
        'tampered\n',
    guarded(
        DOUBLE, 'double', 42, DOUBLE_42,
        'if (/(\\d+)/.test("abc 123")) { guarded(1); var k = process.argv[9] || "constructor"; '
        'var R = /x/[k]; console.log("$1=" + R.$1); }\n',
    ):
        '$1=\n',
    guarded(
        DOUBLE, 'double', 42, DOUBLE_42,
        'if (/(\\d+)/.test("abc 123")) { guarded(1); console.log("input=" + RegExp.input.length); }\n',
    ):
        'input=36\n',
    checked_by_name(F'function g(x) {{ h(); }} function h() {{ g.arguments[0].toString = {SET_A_LINE_BREAK}; }} g(N); '):
        'tampered\n',
    checked_by_name(
        F'var o = {{ apply: function (t, a) {{ a.callee.toString = {SET_A_LINE_BREAK}; }} }}; ',
        'o.apply(null, arguments); ',
    ):
        'tampered\n',
    (
        '(function () { var N = function (cb) { arguments[0](); '
        r'const T = function () { const R = new RegExp("\n"); return R["test"](N); }; '
        'if (T()) { console.log("tampered"); } else { console.log("fine"); } }; '
        F'return N(function () {{ this.callee.toString = {SET_A_LINE_BREAK}; }}); }})();\n'
    ):
        'tampered\n',
    checked_by_name(
        'function h() { var p = Error.prepareStackTrace; Error.prepareStackTrace = function (e, s) { return s; }; '
        F'var s = new Error().stack; Error.prepareStackTrace = p; s[1].getFunction().toString = {SET_A_LINE_BREAK}; }} ',
        'h(); ',
    ):
        'tampered\n',
    checked_by_name(F'try {{ throw 0; }} catch (g) {{ var g = N; g.toString = {SET_A_LINE_BREAK}; }} '):
        'tampered\n',
    guarded(
        DOUBLE,
        'double',
        42,
        DOUBLE_42,
        'try { console.log(guarded(21)); } catch (e) { console.log(e.constructor.name); }\n',
        helpers=NEW_HELPERS.replace('var h1 = 0xdeadbeef ^ seed;', 'h1 = 0xdeadbeef ^ seed; let h1;'),
    ):
        'ReferenceError\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestASelfCheckTrippedThroughAMadeUpRouteStillTrips(TestBase):

    @wontfix(
        'every route here was made up to reach the check: no obfuscated file reaches a prototype '
        'through __proto__ of a function literal, builds the caller key at runtime, rebuilds an empty '
        'function spread over two lines, reads the match statics a hash helper leaves behind, reaches '
        'the checked function through legacy arguments, arguments.callee, a stack trace or a catch '
        'parameter, or reads a variable of a hash helper before it is declared'
    )
    def test_the_check_still_trips(self):
        rows = A_SELF_CHECK_TRIPPED_THROUGH_A_MADE_UP_ROUTE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


AN_ASSIGNMENT_TO_A_CONSTANT_INSIDE_A_TRY = {
    a_program("""
        function f(q) {
          const [a] = q;
          try { a = 2; return 'assigned'; } catch (e) { return e.constructor.name; }
        }
        console.log(f([1]));
        """): 'TypeError\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnAssignmentToAConstantStillThrows(TestBase):

    @backlog
    def test_the_assignment_still_throws(self):
        rows = AN_ASSIGNMENT_TO_A_CONSTANT_INSIDE_A_TRY
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


A_CALL_THAT_ASSIGNS_A_CONSTANT = {
    a_program("""
        function f() {
          const a = 1;
          try { a = 2; return 'assigned' + a; } catch (e) { return e.constructor.name; }
        }
        console.log(f());
        """): ('TypeError\n', None),
    a_program("""
        function f() {
          const a = 1;
          a = 2;
          return a;
        }
        console.log(f());
        """): ('', 'TypeError'),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestACallThatAssignsAConstantStillThrows(TestBase):

    @backlog
    def test_the_evaluated_assignment_still_throws(self):
        rows = A_CALL_THAT_ASSIGNS_A_CONSTANT
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            {source: (behavior, behavior) for source, behavior in rows.items()},
        )


A_NAMESPACE_PROPERTY_NAMED_LIKE_A_PARAMETER = {
    a_program("""
        function f(a) { var NS = {}; NS.a = 1; return arguments[0]; }
        console.log(f(5));
        """): '5\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFlattenedNamespaceLeavesTheArgumentsAlone(TestBase):

    @backlog
    def test_the_argument_is_read_back(self):
        rows = A_NAMESPACE_PROPERTY_NAMED_LIKE_A_PARAMETER
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


A_SCRIPT_THAT_ASSIGNS_EVAL = {
    a_program("""
        var x = 1;
        function keep() { eval = eval; }
        eval("console.log(x)");
        """): ('1\n', None),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnEvalTheScriptAssignsIsStillEval(TestBase):

    @wontfix('no program assigns eval to a name of its own, and an obfuscator that hides eval aliases it')
    def test_the_global_the_code_reads_stays(self):
        rows = A_SCRIPT_THAT_ASSIGNS_EVAL
        self.assertEqual(
            {source: before_and_after_in_a_host(source) for source in rows},
            {source: (behavior, behavior) for source, behavior in rows.items()},
        )


A_FUNCTION_ONLY_A_SHADOWING_NAME_SPELLS = {
    a_program("""
        function outer(n) {
          function dec(s) { return s + 1; }
          var other = function (k) { var dec = [k]; return dec.length + n; };
          return other;
        }
        console.log(outer(2)(1));
        """): inspect.cleandoc("""
        function outer(n) {
          var other = function(k) {
            var dec = [k];
            return dec.length + n;
          };
          return other;
        }
        console.log(outer(2)(1));
        """),
}


class TestAFunctionNothingCallsIsRemovedWhateverShadowsItsName(TestBase):

    @opportunity
    def test_the_function_nothing_calls_is_removed(self):
        rows = A_FUNCTION_ONLY_A_SHADOWING_NAME_SPELLS
        self.assertEqual({source: folded(source) for source in rows}, rows)


A_CONCEALED_STRING_THE_PROGRAM_CHANGES = {
    (
        F'var cache = {{}};\nvar table = {TABLE};\n'
        + decoder('decode') + '\n'
        + accessor('acc', 'cache', 'decode') + '\n'
        + 'var early;\n'
        + 'try { early = acc(10); } catch (e) { early = e.constructor.name; }\n'
        + 'var bufferToString = function (b) { return Buffer.from(b).toString("utf-8"); };\n'
        + 'console.log(early, acc(11));\n'
    ):
        'TypeError Fizz\n',
    (
        F'var cache = {{}};\nvar table = {TABLE};\nfunction bufferToString(b) {{ return b.join(","); }}\n'
        + decoder('decode') + '\n'
        + accessor('acc', 'cache', 'decode') + '\n'
        + 'console.log(acc(10));\n'
    ):
        '112,117,115,104\n',
    (
        HEAD
        + F'var other = {OTHER_TABLE};\n'
        + decoder('decode') + '\n'
        + accessor('acc', 'cache', 'decode') + '\n'
        + accessor('acc2', 'cache', 'decode', 'other') + '\n'
        + 'console.log(acc2(10), acc(10));\n'
    ):
        'Fizz Fizz\n',
    (
        'Object.prototype[10] = "polluted";\n'
        + HEAD
        + decoder('decode') + '\n'
        + accessor('acc', 'cache', 'decode') + '\n'
        + 'console.log(acc(10), acc(11));\n'
    ):
        'polluted Fizz\n',
    (
        SLICED
        + 'var o = { bufferToString: function (b) { return "bytes:" + b.length; } };\n'
        + F'with (o) {{ var S_decode = function (str) {{ {decoder_body()} }}; }}\n'
        + slicing('S', 'S_decode') + '\n'
        + 'console.log(S(2, 5), S(16, 4));\n'
    ):
        'bytes:4 bytes:3\n',
    (
        'String.prototype.slice = function (a, b) { return "#ZlH"; };\n'
        + SLICED
        + decoder('S_decode') + '\n'
        + slicing('S', 'S_decode') + '\n'
        + 'console.log(S(2, 5));\n'
    ):
        'log\n',
    (
        DEFAULTED_HEAD
        + defaulted('acc', 'dec', order='w') + '\n'
        + 'function inner() {\n'
        + '  ' + defaulted('acc2', 'dec2', order='w') + '\n'
        + '  return acc2(10);\n'
        + '  ' + decoder('dec2', SWAPPED) + '\n'
        + '}\n'
        + 'console.log(acc(10), inner());\n'
        + decoder('dec') + '\n'
    ):
        'push push\n',
    (
        'Array.prototype[10] = "planted";\n'
        + DEFAULTED_HEAD
        + defaulted('acc', 'dec', order='w') + '\n'
        + 'console.log(acc(10), acc(11));\n'
        + decoder('dec') + '\n'
    ):
        'planted Fizz\n',
    **{
        (
            DEFAULTED_HEAD
            + defaulted('acc', 'dec', order='w0') + '\n'
            + 'var original = Function.prototype.call;\n'
            + F'{call} = function (receiver, index) {{ return "called" + index; }};\n'
            + 'var r = acc.call(undefined, 10);\n'
            + F'{call} = original;\n'
            + 'console.log(r, acc(11));\n'
            + decoder('dec') + '\n'
        ):
            'called10 Fizz\n'
        for call in (
            '(function () {}).constructor.prototype.call',
            'Object.getPrototypeOf(function () {}).call',
            '(function () {}).__proto__.call',
        )
    },
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAConcealedStringIsDecodedAsTheProgramChangesIt(TestBase):

    @wontfix(
        'the obfuscator declares its own function turning UTF-8 bytes into a string, gives every '
        'string an index of its own and writes no prototype; each of these programs is made up for '
        'the defect'
    )
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        rows = A_CONCEALED_STRING_THE_PROGRAM_CHANGES
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


AN_ACCESSOR_NAMED_BY_CODE_EVALUATED_AT_RUNTIME = {
    (
        HEAD
        + decoder('decode') + '\n'
        + accessor('acc', 'cache', 'decode') + '\n'
        + 'console.log(acc(10));\n'
        + 'console.log((0, eval)("typeof acc"));\n'
    ):
        'push\nfunction\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnAccessorCodeEvaluatedAtRuntimeNamesIsKept(TestBase):

    @wontfix('the obfuscator names its machinery with made-up names, which no code evaluated at runtime spells')
    def test_the_host_prints_what_the_script_prints(self):
        rows = AN_ACCESSOR_NAMED_BY_CODE_EVALUATED_AT_RUNTIME
        self.assertEqual(
            {source: before_and_after_in_a_host(source) for source in rows},
            each_program_still_prints(rows),
        )


AN_INDEX_A_MASKED_ARRAY_INHERITS = {
    (
        'Array.prototype[1] = "proto";\n'
        'function f(...m) { m.length = 2; return m[0] + "/" + m[1]; }\n'
        'console.log(f("a"));\n'
    ):
        'a/proto\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAMaskedSlotReadsWhatTheArrayInherits(TestBase):

    @wontfix('no program puts an index on the array prototype that a masked function reads unwritten')
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        rows = AN_INDEX_A_MASKED_ARRAY_INHERITS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAScriptKeptForItsValueEndsOnTheValueOfItsLastStore(TestBase):

    @backlog
    def test_the_script_ends_on_the_value_of_its_last_store(self):
        source = 'var acc;\nacc = 5;\n'
        deobfuscated = deobfuscate_source(source, preserve_script_return=True)
        for evaluation in JsEvaluation:
            with self.subTest(evaluation=evaluation.value):
                self.assertEqual(
                    completion_values([deobfuscated], evaluation),
                    completion_values([source], evaluation),
                )


A_CALL_WRITING_ONLY_ITS_OWN_LOCAL_BESIDE_A_CLASS = {
    a_program("""
        function f() { var t = 0; function inc() { t++; } inc(); class A { v = 1; } return t; }
        f();
        console.log(1);
        """): 'console.log(1);',
    a_program("""
        function f() {
          var t = 0;
          function inc() { t++; }
          inc();
          class A { m() { return 1; } }
          return t;
        }
        f();
        console.log(1);
        """): 'console.log(1);',
}


class TestACallWritingOnlyItsOwnLocalBesideAClassIsRemoved(TestBase):

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_prints_for_each_text_what_it_prints_for_the_program(self):
        rows = A_CALL_WRITING_ONLY_ITS_OWN_LOCAL_BESIDE_A_CLASS
        self.assertEqual(
            {source: behavior(source) for source in rows},
            {source: behavior(text) for source, text in rows.items()},
        )

    @opportunity
    def test_each_program_is_folded(self):
        rows = A_CALL_WRITING_ONLY_ITS_OWN_LOCAL_BESIDE_A_CLASS
        self.assertEqual({source: folded(source) for source in rows}, rows)


A_BRANCH_A_STATIC_BLOCK_NEVER_TAKES = {
    a_program("""
        class C { static { if (false) { console.log(1); } else { console.log(2); } } }
        """): inspect.cleandoc("""
        class C {
          static {
            console.log(2);
          }
        }
        """),
}


class TestABranchAStaticBlockNeverTakesIsRemoved(TestBase):

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_prints_for_each_text_what_it_prints_for_the_program(self):
        rows = A_BRANCH_A_STATIC_BLOCK_NEVER_TAKES
        self.assertEqual(
            {source: behavior(source) for source in rows},
            {source: behavior(text) for source, text in rows.items()},
        )

    @opportunity
    def test_each_program_is_folded(self):
        rows = A_BRANCH_A_STATIC_BLOCK_NEVER_TAKES
        self.assertEqual({source: folded(source) for source in rows}, rows)


A_STATIC_BLOCK_DECLARING_THE_NAME_OF_THE_SCOPE_OBJECT = Program(
    a_program("""
        function wrapper() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope.X = 7;
                    scope.C = class { static { let scope = { X: 1 }; this.v = scope.X; } };
                    a = 30, b = 20;
                    break;
                  case 50:
                    return x = true, scope.C.v;
                }
              }
            }
          }
          var x;
          var result = gen(5, 5)["next"]()["value"];
          if (x) { return result; }
        }
        console.log(wrapper());
        """),
    prints('1'),
    Reading.SCRIPT,
)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestANameAStaticBlockDeclaresIsTheBlocksOwnInARecoveredRun(TestBase):

    @wontfix(
        'the obfuscator generates the name of the scope object, and only a program declaring a name '
        'spelled the same way in a static block inside the flattened function reaches the defect'
    )
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        row = A_STATIC_BLOCK_DECLARING_THE_NAME_OF_THE_SCOPE_OBJECT
        self.assertEqual(row.read(), row.required())


A_KEY_WRITTEN_INTO_THE_OBJECT_PROTOTYPE_THROUGH_ANOTHER_OBJECT = {
    'through the __proto__ of an object literal': Program(
        a_program("""
            var q = {};
            q.__proto__.k = 1;
            var o = {};
            console.log("k" in o);
            """),
        prints('true'),
    ),
    'through the prototype of the prototype of an array': Program(
        a_program("""
            var q = [];
            q.__proto__.__proto__.k = 1;
            var o = {};
            console.log("k" in o);
            """),
        prints('true'),
    ),
    'through Object.getPrototypeOf': Program(
        a_program("""
            var q = {};
            Object.getPrototypeOf(q).k = 1;
            var o = {};
            console.log("k" in o);
            """),
        prints('true'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(
    A_KEY_WRITTEN_INTO_THE_OBJECT_PROTOTYPE_THROUGH_ANOTHER_OBJECT,
    wontfix(
        'no obfuscator writes Object.prototype through another object, and a program asking an '
        'empty literal for a key it put there that way is made up for the defect'
    ),
)
class TestAKeyWrittenIntoTheObjectPrototypeThroughAnotherObjectIsInherited(TestBase):
    pass


A_TYPEOF_OF_A_LOCAL_HOLDING_A_NAME_NOTHING_BINDS = {
    'a local at the top of the file': Program(
        a_program("""
            var r = someGlobal;
            console.log(typeof r);
            """),
        ('', 'ReferenceError'),
    ),
}

A_TYPEOF_OF_A_PACKED_LOCAL_HOLDING_A_NAME_NOTHING_BINDS = {
    'a local of a packed program holding require, run as an ES module': Program(
        a_program("""
            Function("p", "var r = p.r; console.log(typeof r)")({ get r() { return require; } });
            """),
        ('', 'ReferenceError'),
        Reading.ES_MODULE,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_TYPEOF_OF_A_LOCAL_HOLDING_A_NAME_NOTHING_BINDS, todo)
class TestATypeofOfALocalHoldingANameNothingBindsStillThrows(TestBase):
    pass


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_TYPEOF_OF_A_PACKED_LOCAL_HOLDING_A_NAME_NOTHING_BINDS, backlog)
class TestATypeofOfAPackedLocalHoldingANameNothingBindsStillThrows(TestBase):
    pass


A_STRING_TIMER_THE_HOST_REFUSES = {
    'a string timer under Node': Program(
        a_program("""
            try { setTimeout("console.log(1)", 0); } catch (e) { console.log(e.name); }
            """),
        prints('TypeError'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_STRING_TIMER_THE_HOST_REFUSES, backlog)
class TestAStringTimerTheHostRefusesStillThrows(TestBase):
    pass


A_FUNCTION_CALLED_THROUGH_THE_PACKED_ACCESSOR_OBJECT = {
    'a function comparing this with the global object': Program(
        a_program("""
            Function("Q", "globalThis.helper = function () { return this === globalThis; }; console.log(Q['k']());")(
              { get 'k'() { return helper; } }
            );
            """),
        prints('false'),
        Reading.COMMONJS,
    ),
}

#: SECURITY: the packer's output for the program of the row above. It is only ever read as text and
#: never run.
PACKED_THIS = (
    r'Function("cP2i872","globalThis[\"helper\"]=function(){return this===globalThis};return c'
    r'onsole[\"log\"](cP2i872[\"JC7DQ0X\"]());")({get"JC7DQ0X"(){return helper}});'
)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_FUNCTION_CALLED_THROUGH_THE_PACKED_ACCESSOR_OBJECT, todo)
class TestAFunctionCalledThroughThePackedAccessorObjectKeepsItsReceiver(TestBase):

    @backlog
    def test_the_packers_own_output_does_not_call_the_function_bare(self):
        output = deobfuscate_source(PACKED_THIS, execution=ExecutionModel.commonjs)
        self.assertNotIn('helper()', output)


A_FILE_AWAITING_AT_ITS_TOP_LEVEL = {
    'a payload only sloppy code runs as written': Program(
        a_program("""
            await null;
            Function("with ({a: 1}) console.log(a);")();
            """),
        prints('1'),
        Reading.COMMONJS,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_FILE_AWAITING_AT_ITS_TOP_LEVEL, backlog)
class TestAFileAwaitingAtItsTopLevelIsAnEsModule(TestBase):
    pass


#: A program declaring `exports` at its top, mapped to what Node prints for it. `const exports`
#: redeclares a parameter of the CommonJS wrapper, so Node cannot compile the file as CommonJS and
#: runs it as an ES module.
A_FILE_DECLARING_A_WRAPPER_NAME_AT_ITS_TOP = {
    'a const exports nothing reads': Program(
        a_program("""
            const exports = 0;
            console.log(typeof this, typeof require);
            """),
        prints('undefined undefined'),
        Reading.COMMONJS,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFileDeclaringAWrapperNameAtItsTopStaysAnEsModule(TestBase):

    @wontfix(
        'no file is an ES module only by declaring a name of the CommonJS wrapper: a module that '
        'takes one of these names for its own imports what it binds there, which marks it as one'
    )
    def test_the_deobfuscation_behaves_as_the_program_does(self):
        rows = A_FILE_DECLARING_A_WRAPPER_NAME_AT_ITS_TOP
        self.assertEqual(
            {label: row.read() for label, row in rows.items()},
            {label: row.required() for label, row in rows.items()},
        )


A_FUNCTIONS_OWN_VARIABLE_LIFTED_INTO_A_SCRIPT = {
    'a Function body': Program(
        a_program("""
            Function("var helper = [Date.now()]; helper.push(1); console.log(helper.length);")();
            console.log(typeof globalThis.helper);
            """),
        prints('2', 'undefined'),
        Reading.SCRIPT,
    ),
    'a function called once': Program(
        a_program("""
            function f() { var helper = [Date.now()]; helper.push(1); console.log(helper.length); }
            f();
            console.log(typeof globalThis.helper);
            """),
        prints('2', 'undefined'),
        Reading.SCRIPT,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_FUNCTIONS_OWN_VARIABLE_LIFTED_INTO_A_SCRIPT, todo)
class TestAFunctionsOwnVariableStaysOffTheGlobalObject(TestBase):
    pass


A_DIRECT_EVAL_DECLARING_A_FUNCTION_THE_FILE_DECLARES = {
    'a function the file declares after the call': Program(
        a_program("""
            eval("function q() { return 'eval'; }");
            console.log(q());
            function q() { return 'file'; }
            """),
        prints('eval'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFunctionADirectEvalDeclaresAgainReplacesTheFilesOwn(TestBase):

    @wontfix(
        'no program has a direct eval declare again a function the file declares, which replaces '
        'the function only once the eval has run'
    )
    def test_the_deobfuscation_behaves_as_the_program_does(self):
        rows = A_DIRECT_EVAL_DECLARING_A_FUNCTION_THE_FILE_DECLARES
        self.assertEqual(
            {label: row.read() for label, row in rows.items()},
            {label: row.required() for label, row in rows.items()},
        )


A_PACKED_ACCESS_THE_PROGRAM_BEFORE_PACKING_MADE_OTHERWISE = {
    'an update in a class body on a global no write may change': Program(
        a_program("""
            Object.defineProperty(globalThis, 'counter', { value: 0, writable: false });
            try {
              Function("p", "class A { static run() { p.k++; } } A.run(); console.log(p.k);")(
                { get k() { return counter; }, set k(v) { return counter = v; } }
              );
            } catch (e) {
              console.log(e.name);
            }
            """),
        prints('0'),
        Reading.COMMONJS,
    ),
    'a logical assignment of an anonymous function': Program(
        a_program("""
            var handler = 0;
            Function("p", "p.k ||= function () {}; console.log(JSON.stringify(p.k.name));")(
              { get k() { return handler; }, set k(v) { return handler = v; } }
            );
            """),
        prints('""'),
        Reading.COMMONJS,
    ),
    'a compound write in a with body whose object holds the name': Program(
        a_program("""
            Function("p", "p.k = 1; with ({counter: 100}) { p.k += 1; } console.log(p.k);")(
              { get k() { return counter; }, set k(v) { return counter = v; } }
            );
            """),
        prints('2'),
        Reading.COMMONJS,
    ),
    'a read in a with body whose object holds the name': Program(
        a_program("""
            globalThis.counter = 1;
            Function("p", "with ({counter: 100}) { console.log(p.k); }")({ get k() { return counter; } });
            """),
        prints('1'),
        Reading.COMMONJS,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAPackedAccessDoesWhatTheAccessorDid(TestBase):

    @wontfix(
        'the unpacked access is the one the program the packer was given made: a write throws only '
        'where that program threw, a function is named as that program named it, which only a read '
        'of its name tells apart, and a with object holding the name captures it as it did there'
    )
    def test_the_deobfuscation_behaves_as_the_program_does(self):
        rows = A_PACKED_ACCESS_THE_PROGRAM_BEFORE_PACKING_MADE_OTHERWISE
        self.assertEqual(
            {label: row.read() for label, row in rows.items()},
            {label: row.required() for label, row in rows.items()},
        )


A_VARIABLE_A_DIRECT_EVAL_DECLARED_DELETED = {
    'a var the eval declares': Program(
        a_program("""
            eval("var q = 1;");
            console.log(delete q, typeof q);
            """),
        prints('true undefined'),
        Reading.COMMONJS,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAVariableADirectEvalDeclaredCanBeDeleted(TestBase):

    @wontfix(
        'no program deletes a variable by its name, which only sloppy code may write and which '
        'removes only a variable an eval declared'
    )
    def test_the_deobfuscation_behaves_as_the_program_does(self):
        rows = A_VARIABLE_A_DIRECT_EVAL_DECLARED_DELETED
        self.assertEqual(
            {label: row.read() for label, row in rows.items()},
            {label: row.required() for label, row in rows.items()},
        )


A_STRING_RUN_BY_EXECSCRIPT_UNDER_NODE = {
    'a call Node cannot resolve': Program(
        a_program("""
            try { execScript("console.log(1)"); } catch (e) { console.log(e.name); }
            """),
        prints('ReferenceError'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAStringRunByExecScriptRunsOnlyWhereTheHostDefinesIt(TestBase):

    @wontfix('no program run by Node calls execScript, which only Internet Explorer defines')
    def test_the_deobfuscation_behaves_as_the_program_does(self):
        rows = A_STRING_RUN_BY_EXECSCRIPT_UNDER_NODE
        self.assertEqual(
            {label: row.read() for label, row in rows.items()},
            {label: row.required() for label, row in rows.items()},
        )


A_FOLD_RESTING_ON_SLOPPY_CODE_IN_AN_ES_MODULE = {
    'a global finder returning this from a function called bare': Program(
        a_program("""
            function g() { var r; try { r = window; } catch (e) {} return r || this; }
            console.log(g() === globalThis);
            """),
        prints('false'),
        Reading.ES_MODULE,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_FOLD_RESTING_ON_SLOPPY_CODE_IN_AN_ES_MODULE, todo)
class TestAFoldRestingOnSloppyCodeHoldsInAnEsModule(TestBase):
    pass


A_FILE_REQUIRED_THROUGH_ANOTHER_NAME = {
    'a file required through a second name creates the name': Program(
        a_program("""
            var r = require;
            r("fs").writeFileSync(r("path").join(__dirname, "win.js"), "global.window = 1;");
            r("./win.js");
            console.log(typeof window);
            """),
        prints('number'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_FILE_REQUIRED_THROUGH_ANOTHER_NAME, todo)
class TestAFileRequiredThroughAnotherNameIsALoad(TestBase):
    pass


AN_ACCESSOR_BUILT_OVER_VALUES_IT_CLOSES_OVER = {
    'the name is read before the accessor is built': Program(
        a_program("""
            console.log(typeof X);
            var X = function () { var a = [1, 2]; return function (i) { return a[i]; }; }();
            console.log(X(0));
            """),
        prints('undefined', '1'),
        Reading.COMMONJS,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(AN_ACCESSOR_BUILT_OVER_VALUES_IT_CLOSES_OVER, backlog)
class TestAnAccessorBuiltOverValuesItClosesOverIsPromotedOnlyWhereThatHolds(TestBase):
    pass


A_LOADED_FILE_REPLACING_A_BUILTIN = {
    'a required file replaces the split of strings': Program(
        a_program("""
            require("fs").writeFileSync(require("path").join(__dirname, "patch.js"), "String.prototype.split = function () { return [1]; };");
            require("./patch.js");
            console.log("a|b".split("|").length);
            """),
        prints('1'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_LOADED_FILE_REPLACING_A_BUILTIN, backlog)
class TestALoadedFileReplacingABuiltinHoldsTheFoldBack(TestBase):
    pass


A_LENGTH_AN_UNPACKED_REST_PARAMETER_CHANGES = {
    'a rest array the masking writes': Program(
        a_program("""
            function add(...s) { s.length = 2; return s[0] + s[1]; }
            console.log(add.length, add(1, 2));
            """),
        prints('0 3'),
        Reading.COMMONJS,
    ),
    'a function the control-flow recovery gives its parameters': Program(
        a_program("""
            function outer() {
              function* gen(a, b, scope = {NS: {}}, args) {
                while (a + b !== 100) {
                  with (scope.RV || scope) {
                    switch (a + b) {
                      case 10:
                        NS.count = function(...rest) {
                          return gen(20, 30, {NS: scope.NS, Loc: {}}, rest)["next"]()["value"];
                        };
                        return done = true, NS.count;
                        break;
                      case 50:
                        [Loc.first, ...Loc.others] = args;
                        scope.RV = scope.Loc;
                        a = 70, b = 0;
                        break;
                      case 70:
                        return done = true, first + ":" + others.length;
                        break;
                    }
                  }
                }
              }
              var done;
              var result = gen(5, 5)["next"]()["value"];
              if (done) { return result; }
            }
            console.log(outer().length, outer()(1, 2, 3));
            """),
        prints('0 1:2'),
        Reading.COMMONJS,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_LENGTH_AN_UNPACKED_REST_PARAMETER_CHANGES, todo)
class TestAnUnpackedRestParameterKeepsTheLengthOfTheFunction(TestBase):
    pass


AN_ANONYMOUS_FUNCTION_STORED_ON_A_NAMESPACE = {
    "function f() { var B = {}; B.x = function () {}; return '<' + B.x.name + '>'; }\n"
    'console.log(f());':
        '<>\n',
    "function f(r) { var B = {}; [B.x = function () {}] = r; return '<' + B.x.name + '>'; }\n"
    'console.log(f([]));':
        '<>\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnAnonymousFunctionStoredOnANamespaceKeepsItsEmptyName(TestBase):

    @backlog
    def test_the_name_of_the_function_stays_empty(self):
        rows = AN_ANONYMOUS_FUNCTION_STORED_ON_A_NAMESPACE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


A_VAR_REDECLARING_A_PARAMETER_READ_THROUGH_ARGUMENTS = {
    'in separate declarations': Program(
        a_program("""
            function f(a) {
              var x = arguments[0];
              var a = 5;
              var y = arguments[0];
              return [x, y, a].join();
            }
            console.log(f(1));
            """),
        prints('1,5,5'),
        Reading.COMMONJS,
    ),
    'in one declaration': Program(
        a_program("""
            function f(a) {
              var x = arguments[0], a = 5, y = arguments[0];
              return [x, y, a].join();
            }
            console.log(f(1));
            """),
        prints('1,5,5'),
        Reading.COMMONJS,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAVarRedeclaringAParameterWritesTheMappedArguments(TestBase):

    def test_node_prints_what_each_row_pins(self):
        for label, row in A_VAR_REDECLARING_A_PARAMETER_READ_THROUGH_ARGUMENTS.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    @backlog
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        for label, row in A_VAR_REDECLARING_A_PARAMETER_READ_THROUGH_ARGUMENTS.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())


A_STORE_INTO_THE_NAME_OF_A_FUNCTION_DECLARATION = {
    'a number stored before the declaration': Program(
        a_program("""
            function f() {
              x = 2;
              function x() {}
              return typeof x;
            }
            console.log(f());
            """),
        prints('number'),
        Reading.COMMONJS,
    ),
    'undefined stored before the declaration': Program(
        a_program("""
            function f() {
              var x;
              x = undefined;
              function x() {}
              return typeof x;
            }
            console.log(f());
            """),
        prints('undefined'),
        Reading.COMMONJS,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFunctionDeclarationDoesNotStoreWhereItStands(TestBase):

    def test_node_prints_what_each_row_pins(self):
        for label, row in A_STORE_INTO_THE_NAME_OF_A_FUNCTION_DECLARATION.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    @backlog
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        for label, row in A_STORE_INTO_THE_NAME_OF_A_FUNCTION_DECLARATION.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())


A_CHECK_OF_DEFINE_AFTER_CODE_FUNCTION_BUILDS = {
    'through an array': Program(
        a_program("""
            var a = [Function];
            a[0]('globalThis.define = function (f) { console.log(f()); }; globalThis.define.amd = 1;')();
            "function" == typeof define && define.amd ? define(function () { return 'defined'; }) : console.log('none');
            """),
        prints('defined'),
        Reading.COMMONJS,
    ),
    'through a rest parameter': Program(
        a_program("""
            function run(...a) { a.length = 2; return a[0](a[1]); }
            run(Function, 'globalThis.define = function (f) { console.log(f()); }; globalThis.define.amd = 1;')();
            "function" == typeof define && define.amd ? define(function () { return 'defined'; }) : console.log('none');
            """),
        prints('defined'),
        Reading.COMMONJS,
    ),
    'through an object': Program(
        a_program("""
            var a = { f: Function };
            a.f('globalThis.define = function (f) { console.log(f()); }; globalThis.define.amd = 1;')();
            "function" == typeof define && define.amd ? define(function () { return 'defined'; }) : console.log('none');
            """),
        prints('defined'),
        Reading.COMMONJS,
    ),
    'through a parameter': Program(
        a_program("""
            function run(g, s) { return g(s); }
            run(Function, 'globalThis.define = function (f) { console.log(f()); }; globalThis.define.amd = 1;')();
            "function" == typeof define && define.amd ? define(function () { return 'defined'; }) : console.log('none');
            """),
        prints('defined'),
        Reading.COMMONJS,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestACheckOfDefineIsNotDecidedPastCodeFunctionBuilds(TestBase):

    def test_node_prints_what_each_row_pins(self):
        for label, row in A_CHECK_OF_DEFINE_AFTER_CODE_FUNCTION_BUILDS.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    @backlog
    def test_the_deobfuscation_by_the_unit_prints_what_the_program_prints(self):
        for label, row in A_CHECK_OF_DEFINE_AFTER_CODE_FUNCTION_BUILDS.items():
            with self.subTest(label=label):
                self.assertEqual(behavior(deobfuscated_by_the_unit(row.text)), row.prints)


A_TABLE_A_CALL_RETURNS = {
    'a function called in place': with_words(300, a_program("""
        var SC;
        (function () {
          var stringArray = (function () { return "WORDS".split("|"); })();
          SC = function (index) {
            return stringArray[index];
          };
        })();
        console.log(SC(3), SC(299));
        """)),
    'a named call': with_words(300, a_program("""
        var SC;
        (function () {
          function make() { return "WORDS".split("|"); }
          var stringArray = make();
          SC = function (index) {
            return stringArray[index];
          };
        })();
        console.log(SC(3), SC(299));
        """)),
}


class TestATableACallReturnsIsReadByTheAccessorFold(TestBase):

    @opportunity
    def test_each_call_of_the_accessor_folds(self):
        self.assertEqual(
            {
                label: deobfuscate_source(program, execution=ExecutionModel.commonjs)
                for label, program in A_TABLE_A_CALL_RETURNS.items()
            },
            {label: "console.log('w0003', 'w0299');" for label in A_TABLE_A_CALL_RETURNS},
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAMaskedFunctionCalledAsAMethodIsUnmasked(TestBase):

    @opportunity
    def test_the_rest_parameter_of_the_method_is_unpacked(self):
        source = a_program("""
            var L = function () {
              var v = {
                m: function (...a) { a.length = 2; return a[1](a[0]); },
                twice: function (x) { return v.m(x, function (y) { return y * 2; }); }
              };
              return v;
            }();
            console.log(L.twice(21));
            """)
        self.assertNotIn('...a', deobfuscate_source(source, execution=ExecutionModel.commonjs))


A_DECODER_IN_A_SCRIPT_OF_THE_WINDOWS_SCRIPT_HOST = a_program("""
    var decode = function (s) {
      rr = '';
      for (var i = 0; i < s.length; i++) {
        rr += String.fromCharCode(s.charCodeAt(i) ^ 1);
      }
      return rr;
    };
    WScript.Echo(decode('Idmmn'));
    """)


A_NAMESPACE_A_LIBRARY_MAY_HAVE_STORED_BEFORE_THE_FILE = a_program("""
    var NS = NS || {};
    function f(v) { rr = v; NS.go(); return rr; }
    console.log(f(1));
    """)


class TestANameStaysWhereTheFileCallsANamespaceALibraryMayHaveStored(TestBase):

    @todo
    def test_the_name_stays_where_it_is_stored(self):
        self.assertIn('rr = v', folded(A_NAMESPACE_A_LIBRARY_MAY_HAVE_STORED_BEFORE_THE_FILE))


class TestADecoderInAScriptOfTheWindowsScriptHostIsFolded(TestBase):

    @opportunity
    def test_the_call_folds_to_the_string_it_returns(self):
        self.assertIn("WScript.Echo('Hello');", folded(A_DECODER_IN_A_SCRIPT_OF_THE_WINDOWS_SCRIPT_HOST))


class TestAFunctionCalledInParenthesesWhereItIsWrittenIsSummarizedAsItsBody(TestBase):

    @opportunity
    def test_the_function_holding_the_call_is_pure(self):
        cache = ModelCache(JsParser('function f() { var n = 0; (function () { n = n + 1; })(); return n; }').parse())
        self.assertTrue(cache.effects.summary_of(cache.root.body[0]).is_pure)


A_VAR_OF_AN_ENCLOSING_FUNCTION_ONLY_A_NESTED_ONE_USES = a_program("""
    function o() {
      var t;
      function f(n) { t = n * 2; return t; }
      f(1);
      return f(2);
    }
    console.log(o());
    """)


class TestAVarOfAnEnclosingFunctionOnlyANestedOneUsesMovesIntoIt(TestBase):

    @opportunity
    def test_the_call_whose_value_is_discarded_goes(self):
        output = deobfuscate_source(
            A_VAR_OF_AN_ENCLOSING_FUNCTION_ONLY_A_NESTED_ONE_USES,
            execution=ExecutionModel.commonjs,
        )
        self.assertNotIn('f(1)', output)


A_CALLER_READ_UNDER_A_KEY_BUILT_AT_RUN_TIME = Program(
    a_program("""
        var x;
        function g(s) {
          g[s.slice(1)](0);
        }
        function f(n) {
          x = n;
          if (n) g('xcaller');
          console.log(x);
        }
        f(1);
        """),
    prints('0', '0'),
    Reading.COMMONJS,
)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestACallerReadUnderAKeyBuiltAtRunTimeIsSeenToRunTheFunctionAgain(TestBase):

    @wontfix('no program reads the caller of a function under a key it builds at run time')
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        row = A_CALLER_READ_UNDER_A_KEY_BUILT_AT_RUN_TIME
        self.assertEqual(row.deobfuscated(), row.prints)


A_FUNCTION_EXPRESSION_ASSIGNING_TO_ITS_OWN_NAME = Program(
    a_program("""
        var g = function acc(n) {
          acc = n;
          return acc;
        };
        console.log(typeof g(5));
        """),
    prints('function'),
    Reading.COMMONJS,
)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFunctionExpressionAssigningToItsOwnNameKeepsItself(TestBase):

    @wontfix('no program assigns to the name of a function expression inside its body')
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        row = A_FUNCTION_EXPRESSION_ASSIGNING_TO_ITS_OWN_NAME
        self.assertEqual(row.deobfuscated(), row.prints)


A_FILE_LEVEL_VAR_OBSERVED_AS_A_PROPERTY_OF_THE_GLOBAL_OBJECT = {
    'an in test of the global object': Program(
        a_program("""
            var x;
            function f() { x = 1; return x; }
            f();
            console.log('x' in globalThis);
            """),
        prints('true'),
        Reading.SCRIPT,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFileLevelVarObservedAsAPropertyOfTheGlobalObjectStays(TestBase):

    @wontfix('no program tests the global object for a var it declares itself')
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        for label, row in A_FILE_LEVEL_VAR_OBSERVED_AS_A_PROPERTY_OF_THE_GLOBAL_OBJECT.items():
            with self.subTest(label=label):
                self.assertEqual(row.deobfuscated(), row.prints)


A_NAME_NO_DECLARATION_BINDS_OBSERVED_AS_A_PROPERTY_OF_THE_GLOBAL_OBJECT = {
    'an in test of the global object': Program(
        a_program("""
            function f(v) { rr = v; return rr; }
            f(1);
            console.log('rr' in globalThis);
            """),
        prints('true'),
        Reading.SCRIPT,
    ),
    'a toString of the global object': Program(
        a_program("""
            function f(v) { toString = v; return toString; }
            f(function () { return 'patched'; });
            console.log('' + globalThis);
            """),
        prints('patched'),
        Reading.SCRIPT,
    ),
    'a then of the global object': Program(
        a_program("""
            function f(v) { then = v; return then; }
            f(function (resolve) { console.log('then ran'); resolve(1); });
            (async function () { await globalThis; console.log('done'); })();
            """),
        prints('then ran', 'done'),
        Reading.SCRIPT,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestANameNoDeclarationBindsObservedAsAPropertyOfTheGlobalObjectStays(TestBase):

    def test_a_host_prints_what_each_row_pins(self):
        for label, row in A_NAME_NO_DECLARATION_BINDS_OBSERVED_AS_A_PROPERTY_OF_THE_GLOBAL_OBJECT.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    @wontfix('no program tests or converts its global object for a name it stores into itself')
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        for label, row in A_NAME_NO_DECLARATION_BINDS_OBSERVED_AS_A_PROPERTY_OF_THE_GLOBAL_OBJECT.items():
            with self.subTest(label=label):
                self.assertEqual(row.deobfuscated(), row.prints)


A_GLOBAL_OBJECT_LOCKED_OR_HOOKED_THROUGH_A_VALUE_NOT_SEEN_AS_IT = {
    'made non-extensible through the this of a sloppy call': Program(
        a_program("""
            (function () { Object.preventExtensions(this); })();
            function f(v) { rr = v; return rr; }
            try { console.log(f(1)); } catch (e) { console.log(e.constructor.name); }
            """),
        prints('ReferenceError'),
        Reading.SCRIPT,
    ),
    'made non-extensible through a function returning this': Program(
        a_program("""
            function h() { return this; }
            Object.preventExtensions(h());
            function f(v) { rr = v; return rr; }
            try { console.log(f(1)); } catch (e) { console.log(e.constructor.name); }
            """),
        prints('ReferenceError'),
        Reading.SCRIPT,
    ),
    'made non-extensible through apply': Program(
        a_program("""
            Object.preventExtensions.apply(null, [globalThis]);
            function f(v) { rr = v; return rr; }
            try { console.log(f(1)); } catch (e) { console.log(e.constructor.name); }
            """),
        prints('ReferenceError'),
        Reading.SCRIPT,
    ),
    'made non-extensible through forEach': Program(
        a_program("""
            [globalThis].forEach(Object.preventExtensions);
            function f(v) { rr = v; return rr; }
            try { console.log(f(1)); } catch (e) { console.log(e.constructor.name); }
            """),
        prints('ReferenceError'),
        Reading.SCRIPT,
    ),
    'sealed through the this of a sloppy call': Program(
        a_program("""
            (function () { Object.seal(this); })();
            function f(v) { rr = v; return rr; }
            try { console.log(f(1)); } catch (e) { console.log(e.constructor.name); }
            """),
        prints('ReferenceError'),
        Reading.SCRIPT,
    ),
    'the name deleted through a function returning this': Program(
        a_program("""
            function h() { return this; }
            function f(v) { rr = v; delete h().rr; return typeof rr; }
            console.log(f(1));
            """),
        prints('undefined'),
        Reading.SCRIPT,
    ),
    'a prototype set through a function returning this': Program(
        a_program("""
            function h() { return this; }
            Object.setPrototypeOf(h(), {
              set rr(v) { console.log('set ' + v); },
              get rr() { return 'kept'; }
            });
            function f(v) { rr = v; return rr; }
            console.log(f(1));
            """),
        prints('set 1', 'kept'),
        Reading.SCRIPT,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAGlobalObjectLockedOrHookedThroughAValueNotSeenAsItKeepsTheNamesStoredIntoIt(TestBase):

    def test_a_host_prints_what_each_row_pins(self):
        for label, row in A_GLOBAL_OBJECT_LOCKED_OR_HOOKED_THROUGH_A_VALUE_NOT_SEEN_AS_IT.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    @wontfix('no program locks or hooks its own global object and then stores into a name it never declares')
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        for label, row in A_GLOBAL_OBJECT_LOCKED_OR_HOOKED_THROUGH_A_VALUE_NOT_SEEN_AS_IT.items():
            with self.subTest(label=label):
                self.assertEqual(row.deobfuscated(), row.prints)


#: Classic scripts storing into a name no declaration binds where a prototype of the global object
#: holds that name, mapped to what Node prints for each. A sloppy store into a name that a frozen
#: `Object.prototype` holds stores nothing, so `toString` stays a function.
A_NAME_A_STORE_INTO_WHICH_FINDS_WHAT_IS_NOT_SEEN_INSTALLED = {
    'an installer called under a key only the run computes': Program(
        a_program("""
            var k = ['defineProperty'][Date.now() * 0];
            Object[k](Object.prototype, 'rr', {
              get: function () { return 'kept'; },
              set: function (v) { console.log('set ' + v); },
              configurable: true
            });
            function f(v) { rr = v; return rr; }
            console.log(f(1));
            """),
        prints('set 1', 'kept'),
        Reading.SCRIPT,
    ),
    'a name of a frozen Object.prototype': Program(
        a_program("""
            Object.freeze(Object.prototype);
            function f(v) { toString = v; return toString; }
            console.log(typeof f(5));
            """),
        prints('function'),
        Reading.SCRIPT,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestANameAStoreIntoWhichFindsWhatIsNotSeenInstalledStays(TestBase):

    def test_a_host_prints_what_each_row_pins(self):
        for label, row in A_NAME_A_STORE_INTO_WHICH_FINDS_WHAT_IS_NOT_SEEN_INSTALLED.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    @wontfix('no program installs under a key only its run computes, or freezes Object.prototype, and then stores into that name')
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        for label, row in A_NAME_A_STORE_INTO_WHICH_FINDS_WHAT_IS_NOT_SEEN_INSTALLED.items():
            with self.subTest(label=label):
                self.assertEqual(row.deobfuscated(), row.prints)


class TestANameStaysWhereTheProgramReachesTheGlobalObjectOrItsPrototypesUnseen(TestBase):

    @wontfix('no program calls a library through the this of a function called with no receiver')
    def test_a_name_stays_where_a_library_is_called_through_this(self):
        source = a_program("""
            function f(v) { rr = v; this.lib.go(); return rr; }
            console.log(f(1));
            """)
        self.assertIn('rr = v', folded(source))

    @wontfix('no program sets the prototype of a prototype of its window and then stores into a name it never declares')
    def test_a_name_stays_where_the_prototype_of_a_prototype_of_the_window_is_set(self):
        source = a_program("""
            Object.setPrototypeOf(EventTarget.prototype, {
              set rr(v) { console.log('set ' + v); },
              get rr() { return 'kept'; }
            });
            function f(v) { rr = v; return rr; }
            console.log(f(1));
            """)
        self.assertIn('rr = v', folded(source, environment=HostEnvironment.browser))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFunctionRenamedOffAPropertyTheWindowReadsKeepsItsName(TestBase):

    @wontfix('no program reads the name of a function it declares under a name a browser reads')
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        row = Program(
            a_program("""
                Function("function onload() {} console.log(onload.name);")();
                """),
            prints('onload', 'onload=undefined'),
            Reading.WINDOW,
        )
        self.assertEqual(row.deobfuscated(), row.prints)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestANameTakenOffAPropertyTheWindowReadsIsNoNameTheProgramAsksFor(TestBase):

    @wontfix('no program tests the global object for a name it never declares')
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        row = Program(
            a_program("""
                Function("var location = String(Math.random() < 2); console.log(location);")();
                console.log('location_1' in globalThis);
                """),
            prints('true', 'false', 'onload=undefined'),
            Reading.WINDOW,
        )
        self.assertEqual(row.deobfuscated(), row.prints)


A_TABLE_HANDED_BACK_UNDER_A_KEY_KNOWN_ONLY_AT_RUNTIME = {
    inspect.cleandoc('''
        var table;
        table = {
          run: function (p) {
            if (!p) {
              p = function () {
                return 'own';
              };
            }
            return p();
          },
        };
        function dispatch(name) {
          return table[name]();
        }
        console.log(dispatch('run'), dispatch('valueOf').run(function () {
          return 'passed';
        }));
    '''):
        'own passed\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnEntryOfATableHandedBackUnderAKeyKnownOnlyAtRuntimeKeepsWhatItIsHanded(TestBase):

    @wontfix(
        'no obfuscated file selects what a table inherits: the obfuscation keys the table of its '
        'router with random strings of six characters, none of them a name every object inherits, '
        'and no program selects valueOf under a key it reads at runtime to call an entry of the '
        'table it hands back'
    )
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        rows = A_TABLE_HANDED_BACK_UNDER_A_KEY_KNOWN_ONLY_AT_RUNTIME
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


A_RECEIVER_A_BARE_CALL_SUPPLIES_READ_UNDER_A_RUNTIME_KEY = {
    'the indirect eval read off the receiver': Program(
        a_program("""
            function f(k) { return this[k]; }
            var x = 1;
            f('eval')('x = 2');
            console.log(x);
            """),
        prints('2'),
        Reading.SCRIPT,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_RECEIVER_A_BARE_CALL_SUPPLIES_READ_UNDER_A_RUNTIME_KEY, todo)
class TestAReceiverABareCallSuppliesReadUnderARuntimeKeyIsAReflectionSurface(TestBase):
    pass


THE_GLOBAL_OBJECT_RETURNED_BY_A_FUNCTION_AND_HANDED_ON = {
    'a write of String through the handed object': Program(
        a_program("""
            function getG() { var g; try { g = globalThis; } catch (e) { g = this; } return g; }
            function t(x, k, v) { x[k] = v; }
            t(getG(), 'String', { fromCharCode: function () { return 'B'; } });
            console.log(String.fromCharCode(65));
            """),
        prints('B'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'an accessor installed on the receiver a function returns': Program(
        a_program("""
            var G = (function () { return this; })();
            G.__defineGetter__('escape', function () { return function () { return 'X'; }; });
            console.log(escape('a b'));
            """),
        prints('X'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(THE_GLOBAL_OBJECT_RETURNED_BY_A_FUNCTION_AND_HANDED_ON, backlog)
class TestTheGlobalObjectReturnedByAFunctionIsTheGlobalObject(TestBase):
    pass


class TestAReceiverOnlyInstancesSupplyIsNoGlobalObject(TestBase):

    @opportunity
    def test_the_call_folds_under_the_node_host(self):
        deobfuscated = deobfuscate_source(
            inspect.cleandoc("""
                class C { constructor(k) { this[k] = 1; } set(k, v) { this[k] = v; } }
                var key = process.argv.length > 9 ? 'String' : 'x';
                new C(key).set(key, 0);
                console.log(String.fromCharCode(65));
                """),
            execution=ExecutionModel.commonjs,
            environment=HostEnvironment.node,
        )
        self.assertIn("console.log('A');", deobfuscated)


class TestABuiltInStoredIntoAPropertyReadUnderARuntimeKeyStaysIntact(TestBase):

    @opportunity
    def test_the_call_folds(self):
        deobfuscated = deobfuscate_source(
            inspect.cleandoc("""
                var s = {};
                s.b = String;
                var k = process.argv.length > 9 ? 'b' : 'c';
                var t = s[k];
                console.log(t, String.fromCharCode(65));
                """),
            execution=ExecutionModel.commonjs,
            environment=HostEnvironment.node,
        )
        self.assertIn("console.log(t, 'A');", deobfuscated)


A_WRAPPER_NAME_STORED_ON_THE_GLOBAL_OBJECT_FOR_A_LOADED_FILE = (
    a_program("""
        globalThis.__filename = 'set';
        require('./other.js');
        """),
    a_program("""
        console.log(globalThis.__filename);
        """),
)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAWrapperNameStoredOnTheGlobalObjectIsAGlobal(TestBase):

    @wontfix(
        'storing a name the CommonJS wrapper binds onto the global object for another file is made '
        'up for the defect; exposing require for code run through vm, the shape such code takes, keeps '
        'its store'
    )
    def test_the_loaded_file_reads_the_store(self):
        main, other = A_WRAPPER_NAME_STORED_ON_THE_GLOBAL_OBJECT_FOR_A_LOADED_FILE
        rewritten = deobfuscate_source(main, execution=ExecutionModel.commonjs, environment=HostEnvironment.node)
        self.assertEqual(
            (
                module_graph_behavior({'main.js': main, 'other.js': other}, 'main.js'),
                module_graph_behavior({'main.js': rewritten, 'other.js': other}, 'main.js'),
            ),
            (prints('set'), prints('set')),
        )


A_REFLECTIVE_INTRINSIC_REPLACED_UNDER_A_RUNTIME_KEY = {
    'an indirect eval': Program(
        a_program("""
            var k = ['ev', 'al'].join('');
            globalThis[k] = function () { return 'replaced'; };
            console.log((0, eval)('1 + 1'));
            """),
        prints('replaced'),
    ),
    'a Function construction': Program(
        a_program("""
            var k = ['Func', 'tion'].join('');
            globalThis[k] = function () { return function () { return 'replaced'; }; };
            console.log(Function('return 1 + 1')());
            """),
        prints('replaced'),
    ),
    'a direct eval': Program(
        a_program("""
            var k = ['ev', 'al'].join('');
            globalThis[k] = function () { return 'replaced'; };
            console.log(eval('1 + 1'));
            """),
        prints('replaced'),
        Reading.COMMONJS,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(
    A_REFLECTIVE_INTRINSIC_REPLACED_UNDER_A_RUNTIME_KEY,
    wontfix(
        'no program replaces eval or Function through the global object under a key it computes and '
        'then calls the intrinsic by its bare name'
    ),
)
class TestAReflectiveIntrinsicReplacedUnderARuntimeKeyIsNotInlined(TestBase):
    pass


A_GLOBAL_STORED_THROUGH_A_LOCAL_HOLDING_THE_GLOBAL_OBJECT = {
    'in a function expression called with an argument': Program(
        a_program("""
            var x = 1;
            (function (w) {
              var g = globalThis;
              g.x = 2;
              return w;
            })({});
            console.log(x);
            """),
        prints('2'),
        Reading.SCRIPT,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_GLOBAL_STORED_THROUGH_A_LOCAL_HOLDING_THE_GLOBAL_OBJECT, todo)
class TestAGlobalStoredThroughALocalHoldingTheGlobalObjectIsRead(TestBase):
    pass


A_BUILT_IN_A_BASE_CONSTRUCTOR_RETURNS_WRITTEN_THROUGH_THE_RECEIVER = {
    inspect.cleandoc('''
        function A() { return Math; }
        class B extends A { constructor() { void super(); this.max = function () { return 7; }; } }
        new B();
        console.log(Math.max(1, 2));
    '''):
        '7\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestABuiltInABaseConstructorReturnsIsTheReceiverOfTheDerivedOne(TestBase):

    @wontfix(
        'no obfuscated file and no program returns a built-in from a function a class extends to '
        'write through the receiver it becomes; the obfuscation never writes such a class, and '
        'the shape is made up for the defect'
    )
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        rows = A_BUILT_IN_A_BASE_CONSTRUCTOR_RETURNS_WRITTEN_THROUGH_THE_RECEIVER
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


A_FUNCTION_BUILT_UNDER_A_KEY_THE_RUN_READS_LATE = {
    "function k() { return 'constr' + 'uctor'; } var F = [][k()][k()]; F('Math.floor = function () { return 7; }')(); console.log(Math.floor(1.5));": '7\n',
    "var k = ['constructor'][Math.random() < 2 ? 0 : 1]; var F = [][k][k]; F('Math.floor = function () { return 7; }')(); console.log(Math.floor(1.5));": '7\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFunctionBuiltUnderAKeyTheRunReadsLateRunsItsCode(TestBase):

    def test_node_prints_what_each_row_records(self):
        for source, output in A_FUNCTION_BUILT_UNDER_A_KEY_THE_RUN_READS_LATE.items():
            with self.subTest(source=source):
                self.assertEqual(behavior(source), (output, None))

    @backlog
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        rows = A_FUNCTION_BUILT_UNDER_A_KEY_THE_RUN_READS_LATE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


A_BUILT_IN_REPLACED_THROUGH_A_CALLBACK_OR_A_SPELLED_KEY = {
    "[globalThis].forEach(function (g) { g.unescape = function () { return 'X'; }; }); console.log(unescape('%41'));": 'X\n',
    "''[[] + 'constructor'].prototype.toUpperCase = function () { return 'X'; }; console.log('a'.toUpperCase());": 'X\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestABuiltInReplacedThroughACallbackOrASpelledKeyIsNotFolded(TestBase):

    def test_node_prints_what_each_row_records(self):
        for source, output in A_BUILT_IN_REPLACED_THROUGH_A_CALLBACK_OR_A_SPELLED_KEY.items():
            with self.subTest(source=source):
                self.assertEqual(behavior(source), (output, None))

    @wontfix(
        'no obfuscator and no program replaces a built-in through the global object handed to a '
        'callback or through a prototype reached under a key it spells at runtime; the forms code '
        'uses, the global object handed to a function called in place and a name holding it, keep '
        'the call'
    )
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        rows = A_BUILT_IN_REPLACED_THROUGH_A_CALLBACK_OR_A_SPELLED_KEY
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


CODE_HOLDING_AN_INVALID_REGULAR_EXPRESSION = {
    "console.log(1); console.log(Function('return/(/')());": ('1\n', 'SyntaxError'),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestCodeHoldingAnInvalidRegularExpressionIsNotSpliced(TestBase):

    def test_node_does_what_each_row_records(self):
        for source, does in CODE_HOLDING_AN_INVALID_REGULAR_EXPRESSION.items():
            with self.subTest(source=source):
                self.assertEqual(behavior(source), does)

    @wontfix(
        'no obfuscator writes an invalid regular expression into code it runs: the code it builds '
        'is the program it was given, which loads'
    )
    def test_the_deobfuscation_does_what_the_program_does(self):
        rows = CODE_HOLDING_AN_INVALID_REGULAR_EXPRESSION
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            {source: (does, does) for source, does in rows.items()},
        )


A_PAYLOAD_DECLARING_A_VARIABLE = (
    "[]['flat']['constructor']('var q' + ([]['flat'] + '')[9] + ' = 1; console.log(q' + ([]['flat'] + '')[9]"
    " + ', q' + ([]['flat'] + '')[9] + ');')();"
)


class TestAPayloadDeclaringAVariableIsDecodedByTheStrictDeobfuscation(TestBase):

    @opportunity
    def test_the_construction_is_decoded(self):
        decoded = A_PAYLOAD_DECLARING_A_VARIABLE.encode('utf8') | djs(strict=True, environment='node') | str
        self.assertNotIn('constructor', decoded)


class TestOneReadNoFoldDecidesKeepsTheSecondRunFromTheOthers(TestBase):

    @opportunity
    def test_the_read_the_second_run_decides_is_folded(self):
        source = "console.log('abc'[[1]], 'abc'[{}]);"
        self.assertIn(
            source.encode('utf8') | djs() | str,
            (
                "console.log('b', 'abc'[{}]);",
                "console.log('b', void 0);",
            ),
        )


A_BUILT_IN_WRITTEN_THROUGH_WHAT_A_LITERAL_READS = {
    "var S = ''.constructor; S.fromCharCode = function () { return 'X'; }; console.log(String.fromCharCode(65));": 'X\n',
    "''.constructor.fromCharCode = function () { return 'X'; }; console.log(String.fromCharCode(65));": 'X\n',
    "var S = [].constructor; S.isArray = function () { return 'X'; }; console.log(Array.isArray([]));": 'X\n',
    "var N = (0).constructor; N.parseInt = function () { return 'X'; }; console.log(Number.parseInt('5'));": 'X\n',
    "var k = ['__proto__'][0]; [][k].join = function () { return 'X'; }; console.log(['a', 'b'].join('-'));": 'X\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestABuiltInWrittenThroughWhatALiteralReadsIsSeen(TestBase):

    @wontfix(
        'no obfuscated file writes a built-in through a constructor or a prototype it reads off a '
        'literal and then calls what it wrote; the shapes are made up for the defect'
    )
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        rows = A_BUILT_IN_WRITTEN_THROUGH_WHAT_A_LITERAL_READS
        self.assertEqual(
            {source: behavior(source.encode('utf8') | djs() | str) for source in rows},
            {source: (output, None) for source, output in rows.items()},
        )


A_METHOD_REPLACED_BY_A_CALL_THE_SCAN_DOES_NOT_READ_AS_A_WRITE = {
    "Object.assign(JSON, {parse: function () { return 'X'; }}); console.log(JSON.parse('1'));": 'X\n',
    "var k = ['set'][0]; Reflect[k](JSON, 'parse', function () { return 'X'; }); console.log(JSON.parse('1'));": 'X\n',
    "[JSON].forEach(function (o) { o.parse = function () { return 'X'; }; }); console.log(JSON.parse('1'));": 'X\n',
    "function patch(o) { o.keys = function () { return 'X'; }; } patch(Object); console.log(Object.keys({a: 1}));": 'X\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAMethodReplacedByACallTheScanDoesNotReadAsAWriteIsSeen(TestBase):

    @wontfix(
        'no obfuscated file replaces a method of JSON or Object through a copy, a reflective store, '
        'a callback or a helper and then calls it; the shapes are made up for the defect'
    )
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        rows = A_METHOD_REPLACED_BY_A_CALL_THE_SCAN_DOES_NOT_READ_AS_A_WRITE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


A_STORE_ON_A_FUNCTION_NOTHING_READS_WITH_AN_EFFECT = {
    "'use strict'; function f() {} f.name = 'x'; console.log(1);": ('', 'TypeError'),
    "'use strict'; function f() {} f.length = 3; console.log(1);": ('', 'TypeError'),
    "Object.defineProperty(Function.prototype, 'x', {set: function (v) { console.log('set', v); }}); function f() {} f.x = 1;": (
        'set 1\n',
        None,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAStoreOnAFunctionNothingReadsKeepsItsEffect(TestBase):

    @wontfix(
        'no program writes a read-only key of a function in strict code, which throws, or installs '
        'a setter on Function.prototype for a function nothing reads; the shapes are made up for '
        'the defect'
    )
    def test_the_deobfuscation_behaves_as_the_program_does(self):
        rows = A_STORE_ON_A_FUNCTION_NOTHING_READS_WITH_AN_EFFECT
        self.assertEqual(
            {source: behavior(source.encode('utf8') | djs() | str) for source in rows},
            rows,
        )
