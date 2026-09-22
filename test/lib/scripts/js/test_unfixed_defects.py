"""
A ledger of JavaScript defects that are known, understood, and not yet fixed.

The ones a release is held for are not here: `test.lib.scripts.js.test_release_blockers` holds
those, under the same rules, so that the question of whether the tool is fit to ship has one file
for an answer. An entry belongs there rather than here when a program an engine runs comes back
behaving differently over a shape real input plausibly holds. A behavior change only a shape
constructed for the defect reaches stays here whatever it costs, with the judgment of its
unlikelihood written on the entry that carries it; so does one that refuses to reduce
something, reduces it to something uglier, or mishandles a file no engine runs. Which
file an entry sits in says what it costs and never how well it is understood, so an entry moves
across when that is reassessed.

Every ledger entry states what a correct implementation would do, never what the code does today,
and is marked `unittest.expectedFailure`. An entry that starts passing is therefore reported as an
unexpected success, which fails the suite: an entry leaves this file when its defect is fixed and
its marker is removed, and never by quietly ceasing to be true. Alongside the entries the file also
carries companion tests that are not marked — guards pinning the behavior a defect must not spread
to, and engine-anchors checking that a pinned behavior is what an engine really does — and those
pass in the ordinary way.

Where the question is one about JavaScript rather than about this project, the answer was
established with Node.js and is quoted in the docstring of the test that pins it.

An entry is quantified over the rows its defect is about, and where those rows belong to a corpus
some law elsewhere is stated over, they stay in that corpus and are imported here. The module
holding them is named in the docstring of the entry that pins them, and a row rejoins the law the
day the marker comes off.
"""
from __future__ import annotations

import inspect
import unittest

from test import TestBase
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
from test.lib.scripts.js.deobfuscation.test_call_answers_a_wrapper import (
    a_string_array_whose_rotation_runs,
)
from test.lib.scripts.js.deobfuscation.test_namespaces import (
    A_PROPERTY_READ_BELOW_A_BINDING_OF_ITS_OWN_NAME,
    A_READ_INSIDE_A_FUNCTION_BINDING_THE_NAMESPACES_NAME,
)
from test.lib.scripts.js.deobfuscation.test_stringarray import (
    A_PRESET_BESIDE_AN_ACCESSOR_CALL_NOTHING_CAN_ANSWER,
)
from test.lib.scripts.js.ledger import (
    Program,
    Reading,
    a_program,
    a_walk_of,
    an_accessor_at,
    before_and_after,
    before_and_after_in_a_host,
    each_program_still_prints,
    evaluated_in_a_body,
    folded,
    one_expected_failure_per_program,
    dropped_source_characters,
    printed,
    prints,
    well_formed,
)
from test.lib.scripts.js.test_parameter_grammar import (
    A_FUNCTION_EXPRESSION_NAME_ONLY_THE_ENCLOSING_KIND_RESERVES,
)
from test.lib.scripts.js.test_parser_recovery import (
    A_POSITION_NAMING_A_BINDING_THE_FILE_CREATES,
    A_WORD_NO_MODULE_MAY_BIND,
    unread_spans,
)

from refinery.lib.scripts.js.parser import JsParser


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnExpressionNamedByAWordOnlyTheEnclosingKindReservesIsAProgram(TestBase):
    """
    A function expression takes its name from its own kind and not from the kind of the function
    around it, so a plain expression named `yield` standing inside a generator is a program, and so
    is one named `await` inside an async function. Node prints `function` for

        function* g() { var f = function yield() { return 1; }; console.log(typeof f); } g().next();

    and for the `await` twin of it, and reads every file of the corpus this entry is quantified
    over. A directive is no defence for the `await` half, which no strict body reserves.

    The reservation the kind around the expression used to reach the name anyway, leaving the
    expression without one, so that what came back opened `var f = function(() {` — a text Node
    refuses. A declaration's name and a class expression's name are read under whatever encloses
    them instead, which is what makes the four files of
    `test.lib.scripts.js.test_parameter_grammar.A_BINDING_THE_KIND_OF_FUNCTION_RESERVES` no
    programs to begin with.
    """

    def test_printing_one_of_them_gives_a_program_that_runs_the_same_way(self):
        rows = A_FUNCTION_EXPRESSION_NAME_ONLY_THE_ENCLOSING_KIND_RESERVES
        self.assertEqual(
            {source: behavior(printed(source)) for source in rows},
            {source: ('', None) for source in rows},
        )

    def test_the_deobfuscation_of_one_that_prints_keeps_what_it_prints(self):
        """
        A file that asks for the type of the expression keeps it alive through every pass, so what
        the tool writes for this one is what a caller of `refinery.js` is handed.
        """
        source = (
            'function* g() { var f = function yield() { return 1; };'
            ' console.log(typeof f); } g().next();'
        )
        self.assertEqual(before_and_after(source), (('function\n', None), ('function\n', None)))


class TestABindingNamedByAWordNoModuleMayBindIsNoProgram(TestBase):
    """
    An `import` or `export` declaration stands only in module code, and module code is strict with
    no directive saying so, so a binding one of them creates cannot be named by a word strict code
    reserves, by the one word only a module reserves, or by either of the two names strict code
    refuses to bind. `node --check` over a `.mjs` file refuses every word of
    `test.lib.scripts.js.test_parser_recovery.A_WORD_NO_MODULE_MAY_BIND` in every position of
    `A_POSITION_NAMING_A_BINDING_THE_FILE_CREATES` beside it, each with a `SyntaxError`:

        import yield from "m";               Unexpected strict mode reserved word
        import * as enum from "m";           Unexpected reserved word
        import { await } from "m";           Unexpected reserved word
        import { remote as eval } from "m";  Unexpected eval or arguments in strict mode

    The fifth position writes the binding with a `var` of its own before exporting it, so the
    declaration the host names in refusing `var yield;` and `export { yield };` together is that
    one. The same host binds `yield`, `let` and `eval` freely in a sloppy script, which is what
    makes the module and not the word the reason any of these is refused.

    The far side of the same declaration is a different position under no such restriction, a name
    reaching across the module boundary being an IdentifierName rather than one the file could
    refer to: the host reads `import { yield as v } from "m";` and `export * as await from "m";`.
    That half is already answered, by the law
    `TestAModuleTakesAWiderNameAcrossItsBoundaryThanItBinds` of the module the two corpora live in,
    which reads every word of both in every boundary position with no repair. A refusal that
    reaches a name across the boundary therefore turns that law red rather than this entry green.

    The words the language reserves outright are refused in four of the five binding positions,
    and every word only strict code or only a module reserves is refused in all five. What is left
    is the shorthand `import { class } from "m";`, whose one word is a boundary name and a binding
    at once and is read as the boundary name for every word the language reserves outright, so
    that a module binding `class` prints back exactly as it went in. What that costs is that
    `refinery.lib.scripts.is_well_formed` answers `True` for a tree that is not a program, which is
    the domain every fidelity law is stated over, and a consumer reading that tree finds a module
    binding a name no module has.
    """

    @unittest.expectedFailure
    def test_a_binding_named_by_a_word_no_module_may_bind_is_not_a_well_formed_program(self):
        """
        Every file of the product is one the host refuses, and all of them are compared in a single
        answer so that any position or any word left reading is this entry still failing.
        """
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
    """
    A module awaits at its top level (§16.2.1), and the goal symbol is not known while parsing:
    the parser reads the top level of every file under the script context, where `await` is a
    name, so `await 1` is a name with a number pressed against it, which no statement spells, and
    the statement is kept as the text it is. Keeping it is enough for the module to go on behaving
    as it did, which is the half of this asked of an engine and which holds; what does not is that
    `refinery.lib.scripts.is_well_formed` answers `False` for a file a host runs, so no law stated
    over programs reaches this one and no pass reads the statement. The `for await` head at the top
    level is read already; the operator waits for a top level whose goal is open to read `await`
    followed by an expression as the operator.
    """

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_a_module_awaiting_at_its_top_level_still_behaves_so(self):
        """
        Node prints `2` for `export {}; await 1; console.log(2);` read as a module, and prints `2`
        for the text the deobfuscation writes for it.
        """
        source = 'export {}; await 1; console.log(2);'
        self.assertEqual(before_and_after(source, module=True), (prints('2'), prints('2')))

    @unittest.expectedFailure
    def test_a_top_level_await_beside_module_syntax_is_a_well_formed_program(self):
        """
        Node compiles `export {}; await 1;` as a module.
        """
        self.assertEqual(well_formed('export {}; await 1;'), True)


class TestAUsingDeclarationIsAProgram(TestBase):
    """
    A `using` declaration binds a value whose disposer runs when the block holding it is left,
    `await using` awaits that disposer, and `for (using x of y)` disposes on every iteration
    (ECMAScript 2026, explicit resource management). Node runs every program below and prints `2`
    and then `1`; a script may not spell the declaration at its top level, which is why each
    stands in a block or a body. The parser knows no such declaration: `using` is a name with a
    name pressed against it, which no statement spells, so the declaration is kept as the text it
    is. The program still runs as written, but `refinery.lib.scripts.is_well_formed` answers
    `False` for it and no pass reads the declaration. It waits for a node of its own, since a
    removal of a dead binding must see that leaving the block runs the disposer.
    """

    @unittest.expectedFailure
    def test_a_using_declaration_is_a_program_that_disposes_its_value_when_its_block_is_left(self):
        rows = {
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
        self.assertEqual(
            {name: (well_formed(source), before_and_after(source)) for name, source in rows.items()},
            {name: (True, (prints('2', '1'), prints('2', '1'))) for name in rows},
        )


class TestASourcePhaseImportIsAProgram(TestBase):
    """
    `import source x from 'm'` binds `x` to the module source of `m` rather than to its namespace
    (ECMAScript 2026, source phase imports), and Node compiles the file as a module. The parser
    reads `import source x` as a module declaration with no specifier and refuses it, so the
    declaration is kept as the text it is, printed back as written and not a program.
    """

    @unittest.expectedFailure
    def test_a_source_phase_import_prints_back_as_written(self):
        source = "import source x from 'm';"
        self.assertEqual((well_formed(source), printed(source)), (True, source))


class TestALiteralNoElementOfWhichRunsIsCounted(TestBase):
    """
    An array literal's `length` is the number of positions it was written with, and reading it
    discards the array, so the count may replace the read whenever evaluating every element does
    nothing that can be observed. What the fold asks instead is whether every element is written as
    a literal or is an elision, which is narrower: the four reads of
    `test.lib.scripts.js.deobfuscation.test_array_length_reads.A_COUNT_THE_FOLD_DOES_NOT_REACH` hold
    a global value name, a function expression, an object and an array literal, and a getter that is
    defined rather than called, and not one of them runs while the array is built.
    """

    @unittest.expectedFailure
    def test_a_literal_whose_elements_are_not_written_as_literals_is_counted(self):
        """
        Node answers those four reads with `3`, `2`, `1`, and `2`, which the law in that module pins
        against the engine; each is the number of commas the literal is written with.
        """
        counts = A_COUNT_THE_FOLD_DOES_NOT_REACH
        self.assertEqual(
            [folded(F'console.log({read});') for read in counts],
            [F'console.log({count});' for count in counts.values()],
        )


#: A strict body assigning to a name no binding declares, mapped to the behavior Node gives it: the
#: pair of what it prints and what it throws. The write is the same in both and only what the body
#: does about the throw differs, one handling it and one letting it end the program.
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
    """
    A body that opens with the directive runs strict, and an assignment to a name no binding
    declares throws a `ReferenceError` there rather than creating a global. Running that body is how
    the tool answers what a call returns, and the mode the body declares is not carried into the
    run: the write is answered by the sloppy rule, the call is answered with a value it never
    produced, and the file that comes back prints that value where the program it came from threw.

    This is not the directive being lost. It is still written where the file wrote it, and both the
    file handed over and the file handed back declare the same mode; only the answer computed
    between them was computed under the other one.
    """

    @unittest.expectedFailure
    def test_an_assignment_to_an_undeclared_name_throws_in_a_strict_body(self):
        """
        Node prints `threw` for the first program of
        `A_STRICT_BODY_ASSIGNING_TO_AN_UNDECLARED_NAME` and refuses the second with a
        `ReferenceError` having printed nothing: the write is the same in both, and the first body
        catches what it throws while the second lets it end the program. The first deobfuscation
        prints `ok`, the value of the branch the throw never let run, and the second prints `1`,
        having gone on past the statement the file stopped at. The first program with its directive
        left out prints `ok` on both sides.
        """
        rows = A_STRICT_BODY_ASSIGNING_TO_AN_UNDECLARED_NAME
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            {source: (answer, answer) for source, answer in rows.items()},
        )


#: A strict region assigning to one of the global names that is not writable, mapped to the behavior
#: Node gives it: the pair of what it prints and what it throws. The write is refused in every row,
#: so the statement does exactly one thing and that thing is throw. What varies is where the mode
#: comes from, how the assignment is spelled, and whether anything catches what it throws.
A_STRICT_REGION_ASSIGNING_TO_A_NON_WRITABLE_GLOBAL = {
    "'use strict';\nNaN = 1;\nconsole.log(1);\n": ('', 'TypeError'),
    "'use strict';\nundefined = 1;\nconsole.log(1);\n": ('', 'TypeError'),
    "'use strict';\nInfinity = 1;\nconsole.log(1);\n": ('', 'TypeError'),
    "'use strict';\n(NaN) = 1;\nconsole.log(1);\n": ('', 'TypeError'),
    "'use strict';\n[NaN] = [1];\nconsole.log(1);\n": ('', 'TypeError'),
    "'use strict';\n({p: undefined} = {p: 1});\nconsole.log(1);\n": ('', 'TypeError'),
    "(function () { 'use strict'; NaN = 1; console.log(1); })();\n": ('', 'TypeError'),
    "var out = 'L';\nclass C { static { NaN = 1; } }\nconsole.log(out);\n": ('', 'TypeError'),
    "'use strict';\ntry { NaN = 1; console.log('L'); }"
    " catch (e) { console.log(e.constructor.name); }\n": ('TypeError\n', None),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAWriteTheModeRefusesIsNotAWriteThatDoesNothing(TestBase):
    """
    `undefined`, `NaN` and `Infinity` name properties of the global object that no program may
    replace. An assignment to one of them is discarded where the assignment is sloppy code and is a
    `TypeError` where it is strict code, so in a strict region the statement has exactly one effect
    and throwing is it. It is removed in both, and everything the throw stood in front of then runs.

    Which region is strict is not what is misread: the mode is taken from wherever the file puts it
    and the removal follows it everywhere. A directive at the head of the script, one at the head of
    the function body holding the write, and a class static block, which is strict with no directive
    anywhere in the file, are all removed alike.

    Neither is this the removal of a statement that does nothing. The same write to `Object`, `Math`
    or `globalThis` — writable, every one of them — is removed from the same strict position, and
    Node prints `1` for those programs before and after; so is the same write to `NaN` behind a
    `var NaN` that binds the name locally; and so is every one of these writes in a file with no
    directive in it at all. `delete Object.prototype` in that position is left standing, with both
    sides refused by a `TypeError`.
    """

    @unittest.expectedFailure
    def test_an_assignment_to_a_non_writable_global_throws_in_a_strict_region(self):
        """
        Node refuses the first eight programs of
        `A_STRICT_REGION_ASSIGNING_TO_A_NON_WRITABLE_GLOBAL` with a `TypeError` having printed
        nothing, and prints `TypeError` for the last, which catches what the write throws. Every
        deobfuscation goes on past the statement its program stopped at, printing `1` for the first
        seven and `L` for the last two.

        The extent stops at the plain write. `NaN += 1`, `NaN++`, `NaN ||= 1` and `var q = NaN = 1`
        in the same strict position are all left standing and refused on both sides, and so is
        `NaN = 1, 0`, which is the same write with something behind it in the same statement.
        """
        rows = A_STRICT_REGION_ASSIGNING_TO_A_NON_WRITABLE_GLOBAL
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            {source: (answer, answer) for source, answer in rows.items()},
        )


#: A program whose function reads its variables out of a stack hanging off an object rather than out
#: of the rest parameter it declares, mapped to what Node prints for it. The truncation is written on
#: the qualified name and the rest parameter is named nowhere but in the parameter list, so it is the
#: qualified stack that each of these is about. The elements reach the function through the object:
#: one program stores them after the declaration, one writes them into the object literal, one
#: reaches the stack through a chain of two names, one holds two of them, one calls the function
#: twice, and one has the body write an element back for the file to read after the call.
A_STACK_REACHED_THROUGH_A_QUALIFIED_NAME = {
    'var NS = { F: {} };\n'
    'function f(...r) { NS.F.stk.length = 1; return NS.F.stk[0] * 2; }\n'
    'NS.F.stk = [5];\n'
    'console.log(f());\n': '10\n',

    'var NS = { F: { stk: [5] } };\n'
    'function f(...r) { NS.F.stk.length = 1; return NS.F.stk[0] * 2; }\n'
    'console.log(f(3));\n': '10\n',

    'var NS = { stk: [5] };\n'
    'function f(...r) { NS.stk.length = 1; return NS.stk[0] * 2; }\n'
    'console.log(f(3));\n': '10\n',

    'var NS = { F: { stk: [5, 7] } };\n'
    'function f(...r) { NS.F.stk.length = 2; return NS.F.stk[0] + NS.F.stk[1]; }\n'
    'console.log(f());\n': '12\n',

    'var NS = { F: { stk: [5] } };\n'
    'function f(...r) { NS.F.stk.length = 1; return NS.F.stk[0] * 2; }\n'
    'console.log(f() + f());\n': '20\n',

    'var NS = { F: { stk: [5] } };\n'
    'function f(...r) { NS.F.stk.length = 1; NS.F.stk[0] = NS.F.stk[0] + 1; }\n'
    'f();\n'
    'console.log(NS.F.stk[0]);\n': '6\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAStackHangingOffAnObjectIsNotTheArgumentsOfACall(TestBase):
    """
    A function can pack its variables into an array reached through a qualified name instead of into
    the rest parameter it declares. That array belongs to the object, so what it holds is whatever
    the program put there and the call that runs the function need pass nothing at all.

    Unpacking such a function into one taking plain parameters rewrites the callee alone. No call
    site is given the elements the object held, so a read that named a slot of the stack now names a
    parameter nobody passes, and a write that filled one now fills a parameter the object never
    sees. Where the stack is the rest parameter itself the same rewrite is sound, since there the
    elements are exactly the arguments of the call; that is the stack
    `test.lib.scripts.js.deobfuscation.test_restunpack` states its laws over.
    """

    @unittest.expectedFailure
    def test_the_elements_the_object_holds_survive_the_unpacking(self):
        """
        Node prints `10`, `10`, `10`, `12`, `20`, and `6` for the six programs of
        `A_STACK_REACHED_THROUGH_A_QUALIFIED_NAME`. Their deobfuscations print `NaN`, `6`, `6`,
        `NaN`, `NaN`, and `5`: the two programs whose call passes an argument read that argument
        where an element of the object stood, the three that pass none read a parameter no call
        supplies, and the last leaves the object holding the element it started with. The same
        computation with the stack written as the rest parameter itself, `f(...s)` truncated at
        `s.length = 1` and called as `f(5)`, prints `10` on both sides.
        """
        rows = A_STACK_REACHED_THROUGH_A_QUALIFIED_NAME
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


#: A program whose function stores into a stack reached through a qualified name under a key that is
#: no parameter's index, mapped to what Node prints for it. The stack starts empty and the call
#: passes nothing in all but one, where the one index key is a parameter the call is handed the very
#: value the object holds: no element ever has to cross the call boundary, so what any of these
#: reports is the name the rewrite writes and nothing about where a value came from. The keys are an
#: identifier, a string, a negative index, and a decimal that is not the canonical spelling of the
#: one it resembles; the chain is two names long or one; and the last two ask, in a file with no
#: directive in it, how many properties the run left on the global object.
A_QUALIFIED_STACK_KEY_THAT_NAMES_NO_PARAMETER = {
    "'use strict';\n"
    'var NS = { F: { stk: [] } };\n'
    'function f(...r) { NS.F.stk.length = 0; NS.F.stk.a = 3; return NS.F.stk.a; }\n'
    'console.log(f());\n': '3\n',

    "'use strict';\n"
    'var NS = { F: { stk: [] } };\n'
    "function f(...r) { NS.F.stk.length = 0; NS.F.stk['zz'] = 3; return NS.F.stk['zz']; }\n"
    'console.log(f());\n': '3\n',

    "'use strict';\n"
    'var NS = { F: { stk: [] } };\n'
    'function f(...r) { NS.F.stk.length = 0; NS.F.stk[-1] = 3; return NS.F.stk[-1]; }\n'
    'console.log(f());\n': '3\n',

    "'use strict';\n"
    'var NS = { F: { stk: [] } };\n'
    "function f(...r) { NS.F.stk.length = 0; NS.F.stk['01'] = 3; return NS.F.stk['01']; }\n"
    'console.log(f());\n': '3\n',

    "'use strict';\n"
    'var NS = { stk: [] };\n'
    'function f(...r) { NS.stk.length = 0; NS.stk.a = 3; return NS.stk.a; }\n'
    'console.log(f());\n': '3\n',

    "'use strict';\n"
    'var NS = { F: { stk: [] } };\n'
    'function f(...r) { NS.F.stk.length = 0; NS.F.stk.a = 3; NS.F.stk.b = 4;'
    ' return NS.F.stk.a * NS.F.stk.b; }\n'
    'console.log(f());\n': '12\n',

    "'use strict';\n"
    'var NS = { F: { stk: [4] } };\n'
    'function f(...r) { NS.F.stk.length = 1; NS.F.stk.a = 3; return NS.F.stk[0] + NS.F.stk.a; }\n'
    'console.log(f(4));\n': '7\n',

    'var NS = { F: { stk: [] } };\n'
    'function f(...r) { NS.F.stk.length = 0; NS.F.stk.a = 3; return NS.F.stk.a; }\n'
    'var before = Object.getOwnPropertyNames(globalThis).length;\n'
    'f();\n'
    'console.log(Object.getOwnPropertyNames(globalThis).length - before);\n': '0\n',

    'var NS = { stk: [] };\n'
    'function f(...r) { NS.stk.length = 0; NS.stk.a = 3; return NS.stk.a; }\n'
    'var before = Object.getOwnPropertyNames(globalThis).length;\n'
    'f();\n'
    'console.log(Object.getOwnPropertyNames(globalThis).length - before);\n': '0\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnUnpackedStackDeclaresTheLocalsItMints(TestBase):
    """
    Unpacking a rest-array stack turns each key into an identifier, and a key that names no
    parameter turns into an identifier the program never had. Such a name is the rewrite's to
    introduce: a binding for it exists only if the rewrite writes one.

    `refinery.lib.scripts.js.deobfuscation.restunpack.JsRestArrayUnpacking` writes it where the
    stack is a plain local, and writes none where the stack is reached through a qualified name.
    Every key of a qualified stack that is not an index the parameter list covers therefore comes
    back as a bare assignment to a name nothing declares, which is an implicit global where the
    function is sloppy code and a `ReferenceError` where it is strict code.

    This is the second thing that branch gets wrong and it is not the first. What
    `TestAStackHangingOffAnObjectIsNotTheArgumentsOfACall` pins is where a value comes from, an
    element the object held being sought in an argument the call never passed; here every value
    stays inside the body that computes it and only the binding is missing. Declaring the locals
    would leave that entry exactly as it is, and supplying the elements would leave this one exactly
    as it is.
    """

    @unittest.expectedFailure
    def test_a_key_that_names_no_parameter_is_declared_where_it_is_written(self):
        """
        Node prints `3`, `3`, `3`, `3`, `3`, `12` and `7` for the seven strict programs of
        `A_QUALIFIED_STACK_KEY_THAT_NAMES_NO_PARAMETER`, and `0` for the two sloppy ones, which run
        leaving the global object with the properties it already had. Each strict deobfuscation
        throws a `ReferenceError` having printed nothing, the body coming back as `v0 = 3;` and a
        read of `v0` with `v0` declared nowhere in the file; each sloppy one prints `1`, that same
        write having put the name on the global object.

        The same computations with the stack written as the rest parameter itself — `f(...s)` with
        `s.length = 0` and `s.a = 3` — reach the branch that declares what it mints, and print `3`
        and `0` on both sides.
        """
        rows = A_QUALIFIED_STACK_KEY_THAT_NAMES_NO_PARAMETER
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


#: A region that runs strict, holding an assignment to a name no declaration binds, mapped to the
#: behavior Node gives it. Assigning to an unresolvable reference is a `ReferenceError` in strict
#: code where sloppy code creates a property of the global object, so the statement's one effect is
#: the throw and nothing written behind it runs. The mode is arrived at three ways, none of which
#: the statement itself states.
A_STRICT_REGION_ASSIGNING_TO_NO_BINDING = {
    "function f(b) { 'use strict'; var q = b + 1; undeclared_a = 1; return q; }"
    ' console.log(f(2));': ('', 'ReferenceError'),
    "'use strict'; undeclared_b = 1; console.log(3);": ('', 'ReferenceError'),
    'var out = 3; class C { static { undeclared_c = 1; } } console.log(out);':
        ('', 'ReferenceError'),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAWriteOnlyStrictCodeRefusesIsNotADeadStore(TestBase):
    """
    A store whose value nothing reads is removable only where storing is all it does. Where the name
    resolves to no binding and the write stands in strict code the assignment throws instead, and
    the sweep reads it as a store and deletes the throw along with everything the program never
    reached. The same write in sloppy code really is dead, and
    `test_unused.TestAWriteSloppyCodeAnswersIsADeadStore` pins that it is still removed.

    Refusing to remove it is not by itself the fix, and a repair that stops there makes a commoner
    program worse. A namespace flattening rewrites `NS.p = 1` to a bare `p = 1` and emits `var p`
    beside it; where a fold then answers every read of `p`, the declaration is swept as unread.
    Keeping the assignment while its declaration goes leaves a write to a name nothing binds — the
    very throw this entry is about, in a program that had none. The store and its declaration have
    to be decided together.
    """

    @unittest.expectedFailure
    def test_an_assignment_to_no_binding_throws_where_the_region_is_strict(self):
        rows = A_STRICT_REGION_ASSIGNING_TO_NO_BINDING
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            {source: (answer, answer) for source, answer in rows.items()},
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAConstAModuleExportsIsDeadUntilTheModuleRuns(TestBase):
    """
    A function declaration crosses a module boundary at link time: an importer in a cycle with its
    exporter can call the function before the exporter's body has run, and a `const` the function
    reads is then still in its dead zone, so the input throws `ReferenceError`. The model takes the
    export read to stand at the list's statement position, so the fold that puts the constant into
    the function proves its ordering over a walk the cycle never takes, and the deobfuscation
    returns the value where the input threw.

    Kept off the release gate for likelihood: the shape needs an import cycle whose second module
    calls back into the first at its own top level, which a single-file payload — the
    overwhelming shape of obfuscated malware — cannot spell at all. The fix is a link-time
    invocation point in `refinery.lib.scripts.js.analysis.dominance`, priced against every module
    fold there is.
    """

    @unittest.expectedFailure
    def test_the_cycle_still_throws_after_the_fold(self):
        exporter = inspect.cleandoc(
            """
            import { g } from './b.mjs';
            const x = 1;
            export { f };
            function f() { return x; }
            g();
            """
        )
        caller = inspect.cleandoc(
            """
            export function g() {}
            import { f } from './main.mjs';
            console.log(f());
            """
        )
        rewritten = deobfuscate_source(exporter, module=True)
        self.assertEqual(
            (
                module_graph_behavior({'b.mjs': caller, 'main.mjs': exporter}, 'main.mjs'),
                module_graph_behavior({'b.mjs': caller, 'main.mjs': rewritten}, 'main.mjs'),
            ),
            (('', 'ReferenceError'), ('', 'ReferenceError')),
        )


#: A program whose one function reads a global-object alias Node does not put on the global object,
#: mapped to the behavior Node gives it. The read is everything the function does and the call is
#: everything the program does before it prints, so what the read does is all that decides a row.
A_READ_OF_AN_ALIAS_THE_RUNNING_HOST_LACKS = {
    'function f() { return window; }\nf();\nconsole.log(1);\n': ('', 'ReferenceError'),
    'function f() { return self; }\nf();\nconsole.log(1);\n': ('', 'ReferenceError'),
    'function f() { return top; }\nf();\nconsole.log(1);\n': ('', 'ReferenceError'),
    'function f() { return frames; }\nf();\nconsole.log(1);\n': ('', 'ReferenceError'),
}


#: The same program written with `global`, the alias Node defines and a browser does not. Running it
#: decides nothing — both sides print `1` under the only engine this file can ask — so the answer is
#: pinned as the text a correct implementation writes rather than as what an engine makes of it.
A_READ_OF_THE_ALIAS_ONLY_ANOTHER_HOST_LACKS = (
    'function f() { return global; }\nf();\nconsole.log(1);\n'
)


class TestABareGlobalObjectAliasIsNotCertainToResolve(TestBase):
    """
    `window`, `global`, `self`, `top` and `frames` are names a host may put on its global object,
    and no host puts all of them there. A bare read of one may therefore find nothing, and finding
    nothing is a `ReferenceError`: Node refuses `window`, `self`, `top` and `frames`, a browser
    refuses `global`. `SemanticModel.read_may_throw` answers that each of the five may throw — the
    one spelling it vouches for is `globalThis`, which the language mandates in every host and
    `GUARANTEED_GLOBALS` holds. The host-conditional five are answered may-throw, so a function
    whose body only reads one is not a function with no effect, its discarded call is not removed,
    and the declaration stays with it. What comes back throws exactly as the input does.

    The same host assumption used to be made a second time and is refused there too:
    `EffectModel._base_is_safe` no longer clears a property access whose base is one of the five, so
    a bare `window` and a `window.x` agree the read may throw. `JsGlobalFinderInlining` makes the
    third: it folds a global-object finder's call to `globalThis` only where calling the finder
    cannot throw in any host, so a finder that reads a bare host alias on a path some host runs is
    kept. An analyst who names the host with a pin recovers the resolved reading of the alias that
    host defines.
    """

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_a_read_of_an_alias_the_running_host_lacks_still_throws(self):
        """
        Node refuses each program of `A_READ_OF_AN_ALIAS_THE_RUNNING_HOST_LACKS` having printed
        nothing, with a `ReferenceError` reading `window is not defined` and the same for `self`,
        `top` and `frames`. The deobfuscation preserves that: the function around the read, its
        call, and the throw are all kept, so what comes back refuses exactly as the input does.
        """
        rows = A_READ_OF_AN_ALIAS_THE_RUNNING_HOST_LACKS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            {source: (answer, answer) for source, answer in rows.items()},
        )

    def test_a_read_of_the_alias_the_running_host_defines_is_kept_all_the_same(self):
        """
        Node prints `1` for `A_READ_OF_THE_ALIAS_ONLY_ANOTHER_HOST_LACKS` and prints `1` for its
        deobfuscation, so running the two decides nothing about this alias and the text is what
        carries the answer. The text pinned is the one this program takes now that `global` is a
        name the analysis does not vouch for: written with `zzz` in place of `global`, it comes
        back with its read in place and only the layout changed.
        """
        self.assertEqual(
            folded(A_READ_OF_THE_ALIAS_ONLY_ANOTHER_HOST_LACKS),
            inspect.cleandoc(
                """
                global;
                console.log(1);
                """
            ),
        )


#: A program that establishes a global property through one alias and reads it back through
#: another. Node defines `global` and prints `1`, so the answer is pinned as the text a correct
#: implementation writes rather than as what an engine makes of it.
A_GLOBAL_PROPERTY_READ_THROUGH_A_SECOND_ALIAS = (
    'globalThis._V = 1;\nfunction f() { return global._V; }\nf();\nconsole.log(1);\n'
)

#: The same hole reached through a bare assignment rather than a second alias: `foo = 1` mints the
#: global `foo` without naming any alias, so it resolves neither `global` nor any other, and yet
#: `global.foo` collapses to `foo`. Node defines `global` and prints `1`, so the text carries the
#: answer.
A_GLOBAL_PROPERTY_ESTABLISHED_BY_A_BARE_ASSIGNMENT = (
    'foo = 1;\nfunction f() { return global.foo; }\nf();\nconsole.log(1);\n'
)


class TestACrossAliasGlobalPropertyCollapseKeepsItsBaseThrow(TestBase):
    """
    A member read on a host-conditional alias collapses to a bare name only where reading the base
    cannot throw, which a write through the same alias establishes: `global._V = 1; global._V`
    proves `global` resolved before the read, so folding the read to `_V` drops no throw.

    The proof used to be charged to the property's binding, not to the alias that wrote it, so a
    property whose binding was established without resolving the reading alias borrowed a resolution
    it was never given. Two writes did that. A write through a second alias — `globalThis._V = 1`
    establishes `_V` and resolves `globalThis`, and `global._V` then collapsed to `_V` though nothing
    resolved `global`. And a bare assignment — `foo = 1` mints `foo` while naming no alias at all, and
    `global.foo` collapsed just the same. A browser, which lacks `global`, throws a `ReferenceError`
    on the base that either fold had removed. The collapse now additionally requires the base to
    resolve — the host defines it, or every establishing write goes through this same alias spelling —
    so both reads are kept unless the host is pinned to one that defines `global`.
    """

    def test_a_property_read_through_a_second_alias_keeps_its_base_throw(self):
        """
        Node defines `global` and prints `1` for `A_GLOBAL_PROPERTY_READ_THROUGH_A_SECOND_ALIAS`, so
        the engine decides nothing and the text carries the answer. The read `global._V` is kept,
        because the write that established `_V` went through `globalThis` and left `global` unresolved.
        """
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
        """
        Node defines `global` and prints `1` for `A_GLOBAL_PROPERTY_ESTABLISHED_BY_A_BARE_ASSIGNMENT`,
        so the text carries the answer. The read `global.foo` is kept, because the bare `foo = 1` that
        established `foo` resolved no `global`.
        """
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


#: Degenerate global-object finders whose body throws a `TypeError` rather than a `ReferenceError`,
#: each mapped to the text a sound fold writes for it — the call kept in place. `null.x` reads a
#: property off `null`, and `k = globalThis` and `k++` each write a `const`; Node answers all three
#: with a `TypeError`, so calling the finder does not return the global object and rewriting the call
#: to `globalThis` drops the throw. The finder's throw-freedom check reasons only about the
#: `ReferenceError` a host-conditional read raises and is blind to a `TypeError`, so it clears these
#: and folds the call anyway. Charging it to see a member read off a non-object and a write to a
#: constant is what closes the class.
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
    """
    A global-object finder is folded to `globalThis` only where calling it cannot throw, so a finder
    whose body would throw does not qualify. The throw-freedom check sees the `ReferenceError` a
    host-conditional alias read raises but not the `TypeError` a member read off `null`, a write to a
    `const`, or an update of one raises, so a body doing one of those is cleared and its call folded —
    dropping a throw the input would have raised. The fix is to teach the check those `TypeError`
    sources; until then the fold proceeds and the rows below record it.
    """

    @unittest.expectedFailure
    def test_a_finder_whose_body_throws_a_typeerror_is_kept(self):
        rows = A_DEGENERATE_FINDER_THAT_THROWS_A_TYPEERROR
        self.assertEqual({source: folded(source) for source in rows}, rows)


#: A finder whose one global-valued `return` sits in a `try` block that a caught throw skips: reading
#: `window.p` throws where the host lacks `window`, the empty `catch` swallows it, and the finder
#: returns `undefined` rather than a global object. Node prints `undefined`, so a correct
#: deobfuscation keeps the call and prints the same.
A_FINDER_WHOSE_GLOBAL_RETURN_A_CAUGHT_THROW_SKIPS = (
    'function g() { try { window.p; return self; } catch (e) {} }\n'
    'var x = g();\nconsole.log(typeof x);\n'
)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFinderWhoseGlobalReturnACaughtThrowSkipsIsKept(TestBase):
    """
    The finder fold recognizes a function as global-object-valued from its `return` expressions, but a
    `return` inside a `try` block need not be reached: a throw earlier in the block sends control to a
    catching handler that returns nothing, so the finder answers `undefined` in a host where the block
    throws. Folding its call to `globalThis` then substitutes a global object for `undefined` — a value
    divergence, not a dropped throw. Recognition would have to see that a global-valued return the
    finder relies on is not guaranteed to run.
    """

    @unittest.expectedFailure
    def test_a_finder_whose_global_return_is_skipped_by_a_caught_throw_is_kept(self):
        """
        Node prints `undefined` running the input (the caught throw skips `return self`); a correct
        deobfuscation keeps the call and prints the same, so the two agree.
        """
        source = A_FINDER_WHOSE_GLOBAL_RETURN_A_CAUGHT_THROW_SKIPS
        self.assertEqual(before_and_after(source), (('undefined\n', None), ('undefined\n', None)))


#: A reflective `eval` reached through a host-conditional alias base. `window.eval(code)` reads
#: `window` before the call, so where the host lacks it (Node) the whole statement throws a
#: `ReferenceError`. A correct deobfuscation keeps the call and throws the same.
AN_INDIRECT_EVAL_THROUGH_A_HOST_CONDITIONAL_ALIAS = "window.eval('console.log(1);');\n"


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnIndirectEvalThroughAHostConditionalAliasKeepsItsBaseThrow(TestBase):
    """
    `JsReflectionInlining` folds `<alias>.eval(code)` to the code it runs, discarding the base read.
    For `globalThis` that base resolves in every host and the fold is sound, but for a host-conditional
    alias (`window`, `self`, `top`, `frames`, `global`) the base read throws a `ReferenceError` where
    the host lacks the name, and discarding it drops that throw. The reflective-inline site now applies
    the same base-read gate the finder fold and the alias-member collapse already do, so the call is
    kept unless the host is pinned to one that defines the alias. An analyst who names the host with a
    pin recovers the resolved reading.
    """

    def test_an_indirect_eval_through_a_host_conditional_alias_is_kept(self):
        """
        Node throws `ReferenceError: window is not defined` running the input; a correct deobfuscation
        keeps the call and throws the same, so the two agree.
        """
        source = AN_INDIRECT_EVAL_THROUGH_A_HOST_CONDITIONAL_ALIAS
        self.assertEqual(before_and_after(source), (('', 'ReferenceError'), ('', 'ReferenceError')))


#: A program reading a `let` or `const` binding from a point its declaration has not run past,
#: mapped to the behavior Node gives it. The read is reached four ways: through the initializer of a
#: later declarator, through an assignment, through `typeof`, and with no function in the file.
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
    """
    A `let`, `const`, or `class` binding exists from the moment its block is entered and holds no
    value until its declaration runs. A read in between resolves to it and throws a `ReferenceError`
    all the same, which is the one way a name is bound and unreadable at once. So the store holding
    such a read is not dead, the function around it is not empty, and its discarded call is not
    droppable — the deobfuscation keeps them and the throw with them.

    `typeof` is no defence, which is where a dead zone parts company with a name that denotes no
    binding at all. Node prints `1` for

        function f() { let v = 0; v = typeof zzz; } f(); console.log(1);

    where nothing binds `zzz`, and refuses the same program with the read moved into a dead zone. A
    `var` has no dead zone either, being initialized to `undefined` when the body is entered, so
    Node prints `1` for

        function f() { { let v = q; var q = 1; } } f(); console.log(1);

    and for the same program with the declaration written in front of the read; both of those calls
    are discarded rightly.
    """

    def test_a_read_before_the_declaration_runs_still_throws(self):
        """
        Node refuses each program of `A_READ_IN_THE_DEAD_ZONE_OF_A_LEXICAL_BINDING` having printed
        nothing, the `typeof` row included, with a `ReferenceError` reading

            Cannot access 'q' before initialization

        The deobfuscation preserves that: each program's dead-zone read keeps its store, the
        function around it, and its call, so what comes back throws exactly as the input does.
        """
        rows = A_READ_IN_THE_DEAD_ZONE_OF_A_LEXICAL_BINDING
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            {source: (answer, answer) for source, answer in rows.items()},
        )


#: A program whose only throw is a `let`/`const`/`class` read in a function body reached before the
#: declaration runs, mapped to the `ReferenceError` Node ends it with. The read is a dead-zone throw
#: at the call, reached directly and through a transitive callee, for a function, an arrow, and a
#: class binding. A discarded call to such a function — a dead store — must keep the throw.
A_DEAD_ZONE_READ_REACHED_THROUGH_A_CALL = {
    'function f() { return q; }\nvar dead = f();\nlet q = 1;\nconsole.log(2);\n': ('', 'ReferenceError'),
    'function f() { return q; }\nvar dead = f();\nconst q = 1;\nconsole.log(2);\n': ('', 'ReferenceError'),
    'var g = () => q;\nvar dead = g();\nlet q = 1;\nconsole.log(2);\n': ('', 'ReferenceError'),
    'function g() { return q; }\nfunction f() { return g(); }\n'
    'var dead = f();\nlet q = 1;\nconsole.log(2);\n': ('', 'ReferenceError'),
    'var g = () => q;\nvar f = () => g();\n'
    'var dead = f();\nlet q = 1;\nconsole.log(2);\n': ('', 'ReferenceError'),
    'function f() { return C; }\nvar dead = f();\nclass C {}\nconsole.log(2);\n': ('', 'ReferenceError'),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestADeadZoneReadReachedThroughACallStillThrows(TestBase):
    """
    A function whose body reads a `let`/`const`/`class` binding throws a `ReferenceError` when it is
    called before the declaration runs, and so does one whose transitive callee does the read. A
    discarded call to such a function — a dead store — is a call that runs the body, so removing
    it would drop Node's

        Cannot access 'q' before initialization

    and print `2` instead. The effect summary records the outer lexical bindings a call may read
    (`EffectSummary.dead_zone_reads`, unioned across `absorb` so a transitive read carries) and the
    removal's call site refuses the drop unless every such binding's declaration is ordered before
    the call, so each program here keeps its throw.
    """

    def test_a_dead_store_call_to_a_dead_zone_reader_still_throws(self):
        rows = A_DEAD_ZONE_READ_REACHED_THROUGH_A_CALL
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            {source: (answer, answer) for source, answer in rows.items()},
        )


#: A program whose dead-zone reader is called through a dead assignment store (`x = f()` with
#: `x` itself fully dead) rather than a declarator initializer, mapped to the `ReferenceError`
#: Node ends it with. A fully dead assignment target orphans the callee `f` into the removal's
#: `defunct` set, after which the model-free clearance drops a call to that name unconditionally
#: — never consulting the `EffectSummary.dead_zone_reads` gate the declarator path checks.
#: Reached directly, through an array right-hand side, and through a transitive callee.
A_DEAD_ASSIGNMENT_TO_A_DEAD_ZONE_READER = {
    'function f() { return q; }\nvar x;\nx = f();\nlet q = 1;\nconsole.log(2);\n': ('', 'ReferenceError'),
    'function f() { return q; }\nvar x;\nx = [f()];\nlet q = 1;\nconsole.log(2);\n': ('', 'ReferenceError'),
    'function g() { return q; }\nfunction f() { return g(); }\n'
    'var x;\nx = f();\nlet q = 1;\nconsole.log(2);\n': ('', 'ReferenceError'),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestADeadAssignmentToADeadZoneReaderStillThrows(TestBase):
    """
    A dead-zone reader called through a dead assignment store — `x = f()` where `x` is itself
    never read — throws a `ReferenceError` on the call:

        Cannot access 'q' before initialization

    A fully dead assignment target lets the removal orphan the callee `f` into its `defunct`
    set, and the model-free clearance then treats a call to a defunct name as free
    unconditionally, bypassing the `dead_zone_reads` establishment gate the
    declarator-initializer path consults. So the store, the call, and its throw are dropped:
    each program prints `2`. Closing it means gating the defunct-call clearance (or the orphan
    promotion) on the same dead-zone check the declarator path already applies.
    """

    @unittest.expectedFailure
    def test_a_dead_assignment_call_to_a_dead_zone_reader_still_throws(self):
        rows = A_DEAD_ASSIGNMENT_TO_A_DEAD_ZONE_READER
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            {source: (answer, answer) for source, answer in rows.items()},
        )


#: A program folding `o.x` to its literal value where `o` is a `let`/`const` binding read before its
#: declaration, mapped to the `ReferenceError` Node ends it with. The fold rewrites the member access
#: to the value and drops evaluation of the base `o`, whose read is a dead-zone throw.
A_FOLDED_MEMBER_BASE_IN_A_DEAD_ZONE = {
    'function f() { return o.x; }\nf();\nlet o = { x: 1 };\nconsole.log(2);\n': ('', 'ReferenceError'),
    'var y = (function () { return o.x; })();\nlet o = { x: 1 };\nconsole.log(2);\n': ('', 'ReferenceError'),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFoldedMemberBaseReadInADeadZoneStillThrows(TestBase):
    """
    Folding an object-literal property access `o.x` to the property's value discards evaluation of
    the base `o`. Where `o` is a `let`/`const` binding read before its declaration, the base read is
    a dead-zone `ReferenceError`:

        Cannot access 'o' before initialization

    The object fold guards its property values against a dead-zone read but not the base of the
    access it rewrites, so it folds `o.x` to `1` and drops the throw: each program prints `2`.
    """

    @unittest.expectedFailure
    def test_a_folded_member_base_read_before_its_declaration_still_throws(self):
        rows = A_FOLDED_MEMBER_BASE_IN_A_DEAD_ZONE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            {source: (answer, answer) for source, answer in rows.items()},
        )


#: A program writing to a `let`/`const` binding before its declaration runs, mapped to the
#: `ReferenceError` Node ends it with. A write to a lexical binding in its temporal dead zone
#: throws as a read does, but the model flags only reads, so dead-store elimination drops the
#: write. Reached within one scope (a block, an owned binding) and — the twin of the
#: interprocedural read this file's dead-store fix keeps — through a discarded call whose body
#: writes an OUTER lexical binding.
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
    """
    A write to a `let`/`const`/`class` binding before its declaration runs throws a `ReferenceError`
    just as a read does — the assignment to the uninitialized binding — which Node ends the program
    with:

        Cannot access 'x' before initialization

    The read-side flags exclude a write (`SemanticModel.read_may_throw` and `reads_lexical_binding`
    both answer `False` for a write position), and there is no write-side companion, so the store
    `x = 5` is judged dead and removed: each program prints `1` (or `2`). A compound assignment
    reads too and is already kept; only a bare `=` write in the dead zone leaks. This holds for
    a write to an OUTER lexical binding through a discarded call as well: `dead_zone_reads`
    records reads, not writes, so the interprocedural write has no deferred fact and the call is
    dropped — the exact write-side twin of the read the dead-store fix keeps, needing a
    `dead_zone_writes` companion.
    """

    @unittest.expectedFailure
    def test_a_write_before_the_declaration_runs_still_throws(self):
        rows = A_WRITE_IN_THE_DEAD_ZONE_OF_A_LEXICAL_BINDING
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            {source: (answer, answer) for source, answer in rows.items()},
        )


#: Programs asking how many own properties an object literal spelling `__proto__` has, mapped to
#: what Node prints for each. The three spellings answer differently: the shorthand gives the object
#: a property of that name, the two written with a colon set its prototype and give it none, and a
#: computed key gives it one again.
AN_OBJECT_LITERAL_SPELLING_PROTO = {
    'var __proto__ = 7; console.log(Object.keys({ __proto__ }).length);': '1\n',
    "console.log(Object.keys({ '__proto__': 7 }).length);": '0\n',
    'console.log(Object.keys({ __proto__: 1 }).length);': '0\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnObjectLiteralSpellingProtoIsCounted(TestBase):
    """
    `__proto__` written as a key with a colon is not a key at all: it sets the object's prototype
    and the object has no property of that name, so `Object.keys` of such a literal answers one name
    fewer than the literal appears to hold. Written as a shorthand, or with the brackets of a
    computed key, it is an ordinary property like any other.

    Nothing here is answered wrongly — every program comes back doing what it did. What is refused
    is the fold: the interpreter declines a literal spelling that name at all rather than telling
    the three shapes apart, so a program whose whole point is the count comes back with the count
    still in it. The computed spelling is the one it does fold, and it folds correctly.

    `refinery.lib.scripts.js.deobfuscation.helpers.substitute_use_position` is where the shorthand
    is refused expansion, for the same reason and soundly: writing `{ __proto__ }` out as
    `{ __proto__: v }` is a different program.
    """

    @unittest.expectedFailure
    def test_an_object_literal_spelling_proto_folds_to_the_count_it_has(self):
        """
        Node prints `1`, `0` and `0` for the three programs of `AN_OBJECT_LITERAL_SPELLING_PROTO`.
        Each deobfuscation prints the same, and comes back with the literal and the call to
        `Object.keys` still standing where the count could have been.
        """
        rows = AN_OBJECT_LITERAL_SPELLING_PROTO
        self.assertEqual(
            {source: folded(source) for source in rows},
            {source: F'console.log({prints.strip()});' for source, prints in rows.items()},
        )


#: Programs whose `for-in` walk the language alone decides although the file wrote a prototype,
#: mapped to what Node prints for each. A property installed with `Object.defineProperty` and no
#: `enumerable` is not enumerable, and neither is an accessor installed the same way, so neither
#: reaches a walk. A `delete` takes a name off a chain rather than putting one on. And an own key
#: shadows an inherited one of the same name, so a receiver holding its own `z` walks `z` once
#: whatever `Object.prototype` holds.
A_WALK_A_WRITTEN_CHAIN_STILL_DECIDES = {
    a_walk_of('{a: 1}', 'Object.defineProperty(Object.prototype, "z", {value: 9});'):
        'a\n',
    a_walk_of('{a: 1}', an_accessor_at('Object.prototype', 'z')):
        'a\n',
    a_walk_of('{a: 1}', 'delete Object.prototype.toString;'):
        'a\n',
    a_walk_of('{z: 1, a: 2}', 'Object.prototype.z = 9;'):
        'za\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAWalkAWrittenChainStillDecidesIsStillWalked(TestBase):
    """
    A `for-in` is refused wherever the file wrote any prototype the receiver inherits from, which is
    a question about the whole chain where the walk is a question about each name on it. The four
    programs here write one and the walk is still the language's to decide, so each comes back with
    the loop standing where the names could have been folded in its place.

    The refusal is correct and the cost is recall, which is why this is a ledger entry rather than a
    release blocker. Closing it needs the per-name question: whether *this* key is enumerable on the
    chain, and whether the receiver's own slot shadows it. `EffectModel.chain_roots_unwritten` is
    the whole-chain question the walk asks today, and
    `refinery.lib.scripts.js.deobfuscation.interpreter.JsInterpreter._exec_for_in` says as much.
    """

    @unittest.expectedFailure
    def test_a_walk_a_written_chain_still_decides_is_folded(self):
        """
        Node prints `a`, `a`, `a` and `za` for the four programs of
        `A_WALK_A_WRITTEN_CHAIN_STILL_DECIDES`, and each deobfuscation prints the same. What none of
        them comes back as is the one `console.log` of those names that a walk over an untouched
        chain folds to.
        """
        rows = A_WALK_A_WRITTEN_CHAIN_STILL_DECIDES
        self.assertEqual(
            {source: folded(source) for source in rows},
            {source: F"console.log('{prints.strip()}');" for source, prints in rows.items()},
        )


#: Reads whose answer the receiver's own slot decides although the file wrote the chain behind it,
#: mapped to the text each could come back as. The namespace row writes the key onto the object
#: before reading it, so the chain is never consulted; the membership row asks for a name the
#: language puts on every object, which a write to a different key cannot take away.
A_READ_A_WRITTEN_CHAIN_DOES_NOT_REACH = {
    'Object.prototype.z = 9; var o = {}; o.z = 1; console.log(o.z);':
        'Object.prototype.z = 9;\nconsole.log(1);',
    "Object.prototype.q = 1; var o = {}; console.log('toString' in o);":
        'Object.prototype.q = 1;\nconsole.log(true);',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAReadAWrittenChainDoesNotReachIsStillAnswered(TestBase):
    """
    The other half of what the chain gate costs. Namespace flattening and the `in` operator both ask
    whether the file wrote any prototype the receiver inherits from, and hold back every key once
    one was written — including a key the file writes onto the receiver itself, which the chain
    never answers for, and a key on the chain that the write did not touch.

    Restoring this needs a write-side model rather than a wider read-side one: measured in Node, a
    write `o.z = 1` creates an own slot unless the chain holds that key as an accessor or as a
    non-writable data property, and in strict mode those two cases throw a `TypeError` rather than
    silently doing nothing. Until that exists, the own slot cannot be told from the chain's answer.
    """

    @unittest.expectedFailure
    def test_a_read_a_written_chain_does_not_reach_is_folded(self):
        """
        Node prints `1` and `true` for the two programs of `A_READ_A_WRITTEN_CHAIN_DOES_NOT_REACH`,
        and each deobfuscation prints the same. Neither comes back with the answer folded in place
        of the read.
        """
        rows = A_READ_A_WRITTEN_CHAIN_DOES_NOT_REACH
        self.assertEqual(
            {source: folded(source) for source in rows},
            A_READ_A_WRITTEN_CHAIN_DOES_NOT_REACH,
        )


#: A built-in that converts an argument — `Number`, `parseInt`, `String` — runs the same prototype
#: method a bare conversion of that argument would. Each row replaces `Array.prototype.join` with one
#: that returns `'9'`, so converting `[5]` yields `'9'` and every program here prints `9`. The rows
#: are the built-ins whose fold hands the array straight to a specification conversion.
AN_ARRAY_A_BUILTIN_COERCES_THROUGH_A_REPLACED_CHAIN = {
    'number': Program(
        "Array.prototype.join = function () { return '9'; };\nconsole.log(Number([5]));",
        prints('9'),
        Reading.SCRIPT,
    ),
    'parse_int': Program(
        "Array.prototype.join = function () { return '9'; };\nconsole.log(parseInt([5]));",
        prints('9'),
        Reading.SCRIPT,
    ),
    'string': Program(
        "Array.prototype.join = function () { return '9'; };\nconsole.log(String([5]));",
        prints('9'),
        Reading.SCRIPT,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(AN_ARRAY_A_BUILTIN_COERCES_THROUGH_A_REPLACED_CHAIN)
class TestABuiltinCoercingAnArgumentConsultsTheChainThatConvertsIt(TestBase):
    """
    Converting an argument to a primitive runs a prototype method, so a file that replaced
    `Array.prototype.join` decides what `Number([5])`, `parseInt([5])` and `String([5])` compute —
    each `9` here, where the replacement returns `'9'`. The fold hands the array to a specification
    conversion that consults no chain and answers `5` for all three, rewriting a program Node runs
    as `9` into one that prints `5`.

    The interpreter guards this for `String` and `Number` alone, keyed on the callee name, and the
    constant fold that rewrites a top-level call reaches no such guard: the two evaluators split the
    coercion-safety question. The fix is one place both consult — the answer
    `refinery.lib.scripts.js.deobfuscation.helpers.coerces_uninterceptably` already gives, asked
    where an argument is converted rather than at an enumerated callee, so every coercing built-in is
    covered at once.

    Off the release gate: the shape needs an array handed to a coercing built-in together with a
    replaced `Array.prototype` conversion method, which real obfuscation has so far had to be
    constructed to reach. The wrong value it yields is silent, so the entry carries it here.
    """


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestABuiltinTheProgramReplacedIsNotFoldedAsTheIntrinsic(TestBase):
    """
    Guards, not defects: the two ways a program can disturb a built-in that the folds already
    decline, kept beside the coercion entry above because all three ask whether a built-in a call
    reaches is still the one the language describes.
    """

    def test_a_bare_global_written_on_the_global_object_is_not_folded_as_the_builtin(self):
        """
        `globalThis['parseInt'] = f` replaces `parseInt` under a runtime key, so a later `parseInt`
        call names whatever the file installed. Node runs the replacement and prints `42`; the
        deobfuscation leaves the call standing and prints `42` too, rather than folding it to the
        `7` the intrinsic would give.
        """
        source = (
            "globalThis['parseInt'] = function () { return 42; };\n"
            "console.log(parseInt('7'));"
        )
        self.assertEqual(Reading.SCRIPT.read(source), (prints('42'), prints('42')))

    def test_a_literal_receivers_method_survives_a_rebind_of_the_intrinsic_name(self):
        """
        Rebinding the global `Array` to a plain object leaves every existing array's prototype
        untouched, so `[1, 2, 3].join('-')` still means what the language says. Method dispatch is
        keyed on the receiver's type rather than resolved through the `Array` name, so the fold is
        sound: Node prints `1-2-3` before and after.
        """
        source = "Array = {};\nconsole.log([1, 2, 3].join('-'));"
        self.assertEqual(Reading.SCRIPT.read(source), (prints('1-2-3'), prints('1-2-3')))


#: Programs that reach `Object.prototype` through a name the file bound the receiver to, rather than
#: through the literal itself, mapped to what Node prints for each. Reading `__proto__` off a
#: binding, and handing that binding to a `getPrototypeOf` the file also bound, are the same gadget
#: written one indirection further out: what the spelling reaches is decided by the value the
#: binding holds, which the syntax at the write does not show.
A_PROTOTYPE_REACHED_THROUGH_A_BINDING = {
    'var a = {}; a.__proto__.z = 9; var o = {}; console.log(o.z);':
        '9\n',
    'var a = {}; var g = Object.getPrototypeOf; g(a).z = 9; var o = {}; console.log(o.z);':
        '9\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAPrototypeReachedThroughABindingIsStillWritten(TestBase):
    """
    `refinery.lib.scripts.js.deobfuscation.protospelling` writes each spelling that reaches an
    intrinsic prototype out as the name it reaches, which is what puts the write in front of every
    check already looking for one. It reads the receiver from the syntax, so a receiver held in a
    binding is one it declines: `test_a_receiver_the_syntax_does_not_decide_is_left_alone` pins that
    refusal, and these are what the refusal costs.

    Closing it needs the value the binding holds rather than new machinery — the model already
    answers what a binding is assigned, and the pass would consult it where the receiver is a name.
    The same is true of the callee: `g` is `Object.getPrototypeOf` and the file said so.

    Off the release gate deliberately: the one prototype write real obfuscation spells is the
    literal `X.prototype.m = f`, which is read; a write that reaches the prototype through
    a binding has so far had to be constructed to be seen.
    """

    @unittest.expectedFailure
    def test_a_prototype_reached_through_a_binding_answers_the_read(self):
        """
        Node prints `9` for both programs of `A_PROTOTYPE_REACHED_THROUGH_A_BINDING`, each of which
        reaches `Object.prototype` through a name rather than through a literal. Each deobfuscation
        prints `undefined`, and comes back having replaced the read with a variable nothing writes.
        """
        rows = A_PROTOTYPE_REACHED_THROUGH_A_BINDING
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


#: Programs that reach `Object.prototype` by handing it to something that writes it, rather than by
#: writing through a member chain, mapped to what Node prints for each. The prototype is an ordinary
#: argument in each: to `Object.assign`, to `Reflect.set`, to `Reflect.deleteProperty`, and to a
#: function the file declares itself. The last row hands over `Object` rather than its prototype,
#: which reaches the same chain through one more member access and is a route of its own: the write
#: is spelled inside the callee, so nothing at the call site names the property it replaces.
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
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAPrototypeHandedToAWriterIsStillWritten(TestBase):
    """
    A value that escapes into a call may be written by that call. `refinery.lib.scripts.js.analysis
    .effects` records that escape against the *keys* of every name it watches, `Object` among them,
    which is why `EffectModel.global_key_written` refuses each of these — and against the name
    itself only for the roots whose methods a fold is trusted to run, which `Object` is not. So
    `EffectModel.read_chain_intact` reports the chain intact, and every question about it is
    answered from the tables.

    A correct implementation records the escape once, against the name as much as against its keys,
    so that the two questions asked about one escape cannot disagree. Doing that and nothing else
    withdraws every chain answer from a file that hands `Object` to a call it cannot resolve, which
    the real samples do: `test.units.scripting.test_js` measures two of them coming back unreduced.
    So the escape has to be *followed* rather than assumed, which is the interprocedural precision
    this is deferred to — a callee whose writes are enumerable is a callee whose escape is not one.

    Off the release gate deliberately, with the entry above: prototype pollution through a
    writer is exploit vocabulary rather than dropper vocabulary, and no sample family
    observed so far hands its prototype to a call and reads the pollution back.
    """

    @unittest.expectedFailure
    def test_a_prototype_handed_to_a_writer_answers_the_read(self):
        """
        Node prints `9`, `9`, `false`, `9` and `9` for the five programs of
        `A_PROTOTYPE_HANDED_TO_SOMETHING_THAT_WRITES_IT`. Each deobfuscation answers as if the call
        it was handed to had not written it.
        """
        rows = A_PROTOTYPE_HANDED_TO_SOMETHING_THAT_WRITES_IT
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


#: Programs that disable one of the mechanisms a prototype spelling goes through by writing it
#: through another such spelling, mapped to what Node prints for each. The first replaces the
#: `constructor` every plain object inherits, and the second replaces the `__proto__` accessor with
#: an own data property that shadows it; both write `Object.prototype` without naming `Object`.
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
    """
    `refinery.lib.scripts.js.deobfuscation.protospelling` gates each rewrite on
    `refinery.lib.scripts.js.analysis.effects.EffectModel.global_key_written`, which attributes a
    write to the name at the root of the chain it is written through. A chain rooted in a literal is
    attributed to no name, which is the whole reason the pass exists, so a write that disables one
    spelling's mechanism, made through another spelling, is invisible to the gate that would have
    refused it. The pass then rewrites a read of a mechanism the file had already replaced.

    Rewriting the write first closes only what the order reaches. The pass does re-read the models
    per rewrite, so a write spelled where the walk meets it before the read is attributed in time
    and the read behind it is refused —
    `test.lib.scripts.js.deobfuscation.test_protospelling` pins that much. What no order answers is
    the rest: the gate is a question about the whole program and the write may stand anywhere the
    walk reaches after the read, which the rows here are written to stand at.

    Closing it means attributing the write rather than rewriting it — teaching
    `refinery.lib.scripts.js.analysis.effects` that a member chain rooted in a literal receiver is
    rooted at the name `_PROTOTYPE_OWNERS` gives that receiver's prototype, so that one model build
    sees both spellings. The same step answers `var a = {}; a.__proto__.z = 9`, which
    `TestAPrototypeReachedThroughABindingIsStillWritten` records the pass as unable to read.
    """

    @unittest.expectedFailure
    def test_a_mechanism_written_through_a_spelling_is_still_written(self):
        """
        Node prints `5` and `undefined` for the two programs of
        `A_MECHANISM_WRITTEN_THROUGH_A_SPELLING_OF_ITS_OWN`, and each deobfuscation prints the
        same. Each comes back having rewritten a read whose mechanism the file replaced, and prints
        the answer that read has with the mechanism left alone.
        """
        rows = A_MECHANISM_WRITTEN_THROUGH_A_SPELLING_OF_ITS_OWN
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


#: An accessor installed on a locally-declared empty object the file reaches only in member position,
#: mapped to what Node prints for each. The installing call is a member access itself, and the key it
#: installs is what the program reads or writes afterwards: a getter whose read the program prints,
#: a setter whose write runs program code, and a getter installed under a key held in a binding the
#: read resolves.
AN_ACCESSOR_INSTALLED_ON_A_NAMESPACE_OBJECT = {
    'var o = {};\n'
    'o.__defineGetter__("x", function () { return 9; });\n'
    'console.log(o.x);\n': '9\n',

    'var p = {};\n'
    'p.__defineSetter__("y", function (v) { console.log("set", v); });\n'
    'p.y = 5;\n': 'set 5\n',

    'var q = {};\n'
    'var k = "z";\n'
    'q.__defineGetter__(k, function () { return 3; });\n'
    'console.log(q[k]);\n': '3\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnAccessorInstalledOnANamespaceObjectIsStillRead(TestBase):
    """
    An empty object literal reached only in member position is flattened into bare variables by
    `refinery.lib.scripts.js.deobfuscation.namespaces.JsNamespaceFlattening`, whose safety check
    asks only what positions the receiver appears in. The receiver of an install passes it — `o` in
    `o.__defineGetter__("x", f)` stands in member position — and `__defineGetter__` is a name every
    plain object inherits, so the install statement is held back and survives with the object. The
    key it installs does not survive: `o.x` becomes a bare `x` the install never feeds, a read
    answers `undefined` where the getter answered, and a setter's write is dead-store-eliminated
    along with the code it ran. What a correct implementation does is keep every read and write of
    an installed key through the namespace member, since the member is the only spelling that
    reaches the accessor.

    Closing it needs the installed key held back on the object — a recognition of the install among
    the collected properties, not a new question. The `Object.defineProperty(o, "x", {...})` spelling
    is already safe, and for a different reason: the receiver is handed to the call as a bare
    identifier, which the check refuses, so the file comes back whole.

    Off the release gate deliberately: no obfuscator emission witnessed installs an accessor on a
    locally-declared empty namespace object, and the installs the real files carry are on intrinsic
    prototypes, which the chain gates already hold back.
    """

    @unittest.expectedFailure
    def test_the_read_and_write_an_accessor_installed_on_the_namespace_answers(self):
        """
        Node prints `9`, `set 5` and `3` for the three programs of
        `AN_ACCESSOR_INSTALLED_ON_A_NAMESPACE_OBJECT`. Each deobfuscation prints `undefined`,
        nothing, and `undefined`.
        """
        rows = AN_ACCESSOR_INSTALLED_ON_A_NAMESPACE_OBJECT
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_receiver_handed_to_the_install_is_left_standing(self):
        """
        Node prints `7` for the program, and the deobfuscation prints the same, coming back with
        the object and its read in place: the receiver is handed to `Object.defineProperty` as a bare
        identifier, which the flattener's safety check refuses, so the install and the read it feeds
        survive together.
        """
        source = (
            'var p = {};\n'
            'Object.defineProperty(p, "y", { get: function () { return 7; } });\n'
            'console.log(p.y);\n'
        )
        self.assertEqual(before_and_after(source), (prints('7'), prints('7')))


class TestTheStringArrayMachineryGoesOnceNothingReadsIt(TestBase):
    """
    `refinery.lib.scripts.js.deobfuscation.stringarray` keeps the array function, the accessor and
    the rotation IIFE while any of their names is still referenced, which is what
    `test.lib.scripts.js.deobfuscation.test_infrastructure_removal` states. The rows it keeps them
    for reach the end of a run with nothing referencing them after all: the reference stood in a
    function that was itself unreachable, and dead-code elimination took the function, and then the
    accessor, away. What is left is an array holder and a loop that rotates its contents, reachable
    from nothing and printed out in full.

    The pass cannot pick the work up again, because it recognizes the pattern by its accessor and
    there is no longer one. Closing it means the cleanup deciding from the array function and the
    rotation alone, and that in turn means proving the rotation loop terminates without the
    accessor calls its checksum is written in terms of — the simulation is what proves it today,
    and deleting a loop nothing proved terminates is the trade this pass just stopped making.
    """

    @unittest.expectedFailure
    def test_the_preset_folds_to_the_one_statement_it_computes(self):
        """
        Every string the program reads is resolved and the function reading the rest is
        unreachable, so nothing the machinery holds is read and the program is one call to
        `console.log`.
        """
        self.assertEqual(
            "console.log('test string');",
            deobfuscate_source(A_PRESET_BESIDE_AN_ACCESSOR_CALL_NOTHING_CAN_ANSWER),
        )


#: A call to a wrapper whose answer nothing keeps the wrapping of: the first `await`s it, and
#: awaiting a promise and awaiting the value it resolves to differ only in how many turns pass; the
#: second discards it, and a promise nobody holds is a value nobody reads. Each is mapped to the text
#: a fold that could see the call site would produce, measured by answering
#: `refinery.lib.scripts.js.model.wraps_return` with False.
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
    """
    Refusing to answer a call to an `async` function is decided from the callee, and there are two
    call sites where the wrapping the callee adds is taken back off at once: an `await`ed call, and a
    call whose value is discarded. Both are reductions the guards give up, and the second is the one
    that costs triage — a downloader whose URL the fold used to surface now keeps the URL inside a
    body nothing reads out.

    Recovering them means a rule about the call site rather than about the callee, and the call site
    does not settle it on its own. A discarded wrapper that throws gives an unhandled rejection after
    the statement that follows it, where the direct call throws before it; an `await`ed one differs
    from its inlined form by up to two turns when the return is itself promise-valued. Terser
    (`inline.js:352`) and Closure (`InlineFunctions.java:357-362`) both refuse on the same predicate.
    """

    @unittest.expectedFailure
    def test_a_call_whose_wrapping_is_taken_off_is_answered(self):
        rows = A_WRAPPING_THE_CALL_SITE_TAKES_BACK_OFF
        self.assertEqual({source: folded(source) for source in rows}, rows)


class TestAStringArrayHolderNoLoopReadsIsStillResolved(TestBase):
    """
    The string array's rotation loop is what reads what the holder answered, and an `async` holder
    answers a promise, which has no `shift`. Where the loop actually turns the array over that makes
    the program throw, which is what
    `test.lib.scripts.js.deobfuscation.test_call_answers_a_wrapper` states. Where the checksum meets
    its target on the first pass the loop never touches the promise, the holder has already replaced
    itself with a plain function, and every later read answers the array — so the strings are
    resolvable and are no longer resolved.

    Separating the two means deciding whether the loop rotates before deciding whether the holder may
    be read, which is the rotation simulation the pass runs after it has recognized the holder.
    """

    @unittest.expectedFailure
    def test_a_holder_the_rotation_never_reads_is_answered(self):
        """
        Node prints `3`: the loop breaks on its first pass, so `arr` being a promise is never read,
        and `A` has replaced itself with the plain function every later call reads.
        """
        self.assertEqual(
            "console.log('3');",
            folded(a_string_array_whose_rotation_runs('async function', target=3)),
        )


def _spelled_with_an_escaped_identifier(source: str) -> str:
    """
    *source* with each placeholder replaced by the unicode escape spelling the characters it names.

    The escapes are assembled from `chr(92)` rather than written out, because an escape written into
    this file is one flattening away from being the characters it denotes, and an entry that no
    longer holds the spelling it asks about asks nothing at all. A source that named a placeholder
    and came back without a backslash is that flattening having happened, and it is refused here
    rather than left to be discovered as an entry that quietly stopped asking anything.
    """
    result = source.replace('ESCAPED_IF', F'{chr(92)}u0069f')
    result = result.replace('ESCAPED_AIT', F'{chr(92)}u0061it')
    result = result.replace('ESCAPED_ET', F'{chr(92)}u0065t')
    if result != source and chr(92) not in result:
        raise AssertionError(F'the escape in {source!r} was flattened away')
    return result


#: Files the language refuses although nothing in them was fabricated by the parser, each mapped to
#: whether it is a module. Every one of them parses cleanly: what refuses them is an early error,
#: which is a rule about a tree rather than about the text a parser could not read.
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


#: Binding positions written as an object pattern whose shorthand names a reserved word. The one
#: node the parser builds there is the key and the binding at once, so the refusal that reaches
#: every other binding position — a declarator, an array pattern, a parameter — does not reach this
#: one, and `var { if: x } = o` is a program, which is why the refusal cannot simply move onto the
#: key.
A_BINDING_PATTERN_NAMING_A_RESERVED_WORD = tuple(
    _spelled_with_an_escaped_identifier(source) for source in (
        'var { ESCAPED_IF } = { if: 7 }; console.log(1);',
        'var { ESCAPED_IF = 1 } = {}; console.log(1);',
        'function f({ ESCAPED_IF }){ return 1; } console.log(f({}));',
    )
)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFileRefusedWithNothingFabricatedIsNotAnsweredWithAProgram(TestBase):
    """
    A file can parse with every token the source wrote and still be one no engine runs, because the
    rule refusing it is stated over the tree rather than over the text: a name whose escapes spell a
    reserved word, a `let` binding named `let`, two `__proto__` keys in one literal, and a module
    binding `await` are all read without anything being repaired or invented.

    `refinery.lib.scripts.is_well_formed` answers `True` for each, which is the honest answer to the
    question it asks — nothing was fabricated — and the wrong answer to the one every caller wants,
    which is whether the tree spells a program. What follows from that is a file the analyst is
    handed as though it ran: each of these comes back reduced, with the one thing wrong with it
    removed along with the code it stood in.

    `test.lib.scripts.js.test_parser_recovery` states the other half, where the parser did supply
    something and says so. Closing this one needs a refusal mechanism that does not exist yet, and
    the escaped-name row shows the shape it must have: the parser answers with the span it read
    wherever the model has a node kind for one, and a declared function's name is a slot that holds
    an identifier and nothing else.
    """

    @unittest.expectedFailure
    def test_a_file_the_language_refuses_is_refused(self):
        """
        Node refuses every program of `A_FILE_REFUSED_WITH_NOTHING_FABRICATED` with a `SyntaxError`
        and prints nothing for it. Each deobfuscation prints `2`.
        """
        rows = A_FILE_REFUSED_WITH_NOTHING_FABRICATED
        refused = ('', 'SyntaxError')
        self.assertEqual(
            {source: before_and_after(source, module=module) for source, module in rows.items()},
            {source: (refused, refused) for source in rows},
        )

    @unittest.expectedFailure
    def test_a_pattern_binding_a_reserved_word_is_no_program(self):
        """
        Node refuses every program of `A_BINDING_PATTERN_NAMING_A_RESERVED_WORD`, each of which
        binds a name whose escapes spell `if` through an object pattern. What each comes back as is
        refused too, so nothing runs that should not; what is wrong is that
        `refinery.lib.scripts.is_well_formed` answers `True` for all three, and that answer is what
        decides whether such a text may be spliced into a file that does run.
        """
        rows = A_BINDING_PATTERN_NAMING_A_RESERVED_WORD
        self.assertEqual(
            {source: well_formed(source) for source in rows},
            {source: False for source in rows},
        )


#: A self-disabling wrapper called inside a `with` body whose scope object carries the wrapper's
#: name, mapped to what Node prints for it.
A_WITH_OBJECT_CARRYING_A_WRAPPER_NAME = {
    "var o = { W: function (a) { console.log('real', a); } };\n"
    'function W() { W = function () {}; }\n'
    'with (o) { W(1); }\n': 'real 1\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAWithObjectMayCarryTheNameAWrapperAnswersTo(TestBase):
    """
    A call inside a `with` body reads the scope object first, and the wrapper only where the object
    lacks the name. The wrapper expansion assumes the object lacks it. The assumption is
    deliberate: the files the pass exists for call their wrappers inside `with` dispatch blocks
    whose objects never carry the wrapper's name - an obfuscator that put it there would break its
    own program - and refusing every call a `with` body makes is measured to forfeit the whole
    recovery of one of the three real samples. Deciding the property's absence instead would take
    interprocedural object facts the analysis does not have.
    """

    @unittest.expectedFailure
    def test_a_call_the_scope_object_answers_is_left_standing(self):
        """
        Node prints `real 1` for the program of `A_WITH_OBJECT_CARRYING_A_WRAPPER_NAME`: the scope
        object's own `W` answers the call. The deobfuscation lowers the call to its argument and
        prints nothing.
        """
        rows = A_WITH_OBJECT_CARRYING_A_WRAPPER_NAME
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_call_the_scope_object_does_not_answer_is_still_expanded(self):
        """
        The acceptance's other half, and the fizzbuzz-03 recovery in miniature: where the scope
        object lacks the name, the call is the wrapper's and still expands. A guard refusing every
        call a `with` body makes would flip the entry above to an unexpected success by forfeiting
        exactly this.
        """
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


#: A self-disabling wrapper rebound by a direct `eval` of a string no fold can read, mapped to
#: what Node prints for it.
A_WRAPPER_REBOUND_BY_AN_UNREADABLE_EVAL = {
    'function W() { W = function () {}; }\n'
    'eval(String(Math.random() < 2 && "W = function (a) { console.log(7, a); }"));\n'
    'W(1);\n': '7 1\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnUnreadableEvalMayRebindAWrapper(TestBase):
    """
    A direct `eval` of a string nothing can fold may write any name in its scope, so after one
    runs, a wrapper's name may hold anything. The wrapper expansion accepts this: it is the
    acceptance namespace flattening and the dispatcher unwrapper already record, made because a
    reflective surface is exactly what the real obfuscated files carry on the way in, and a pass
    gated on one never runs and never clears the surface that was gating it. An `eval` a fold can
    read is not covered here: its assignment is inlined as real code before the expansion decides,
    and the expansion then sees the write.
    """

    @unittest.expectedFailure
    def test_a_call_after_the_eval_reaches_what_it_bound(self):
        """
        Node prints `7 1` for the program of `A_WRAPPER_REBOUND_BY_AN_UNREADABLE_EVAL`: the `eval`
        argument always evaluates to an assignment rebinding `W`. The deobfuscation lowers the
        call to its argument and prints nothing.
        """
        rows = A_WRAPPER_REBOUND_BY_AN_UNREADABLE_EVAL
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_the_eval_argument_is_still_unread(self):
        """
        The entry above pins the acceptance only while nothing reads the string: a fold that
        learns to decide `Math.random() < 2` would flip it to an unexpected success by making the
        rebind visible, not by closing the acceptance. This holds the string unread.
        """
        source, = A_WRAPPER_REBOUND_BY_AN_UNREADABLE_EVAL
        self.assertEqual(
            folded(source),
            'eval(String(Math.random() < 2 && "W = function (a) { console.log(7, a); }"));\n1;',
        )


#: A self-disabling wrapper called inside a `with` body whose scope object lacks the wrapper's name
#: but watches it being looked for, mapped to what Node prints for it.
A_WITH_OBJECT_WATCHING_FOR_A_WRAPPER_NAME = {
    "var o = new Proxy({}, { has: function (t, k) { console.log('asked', k); return false; } });\n"
    'function W() { W = function () {}; }\n'
    'with (o) { W(console.log(1)); }\n'
    'console.log(2);\n': 'asked W\nasked console\n1\n2\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAWithObjectMayWatchForTheNameAWrapperAnswersTo(TestBase):
    """
    The other half of what a `with` body costs, and the half its scope object does not have to carry
    the name to observe: a call inside the body asks the object for every name it spells, and an
    object can answer that question with code. Expanding the call takes the question away, so a
    program that watched for the wrapper's name stops being asked it.

    This is the acceptance `TestAWithObjectMayCarryTheNameAWrapperAnswersTo` records, priced the
    same way and closed the same way: refusing every call a `with` body makes forfeits the whole
    recovery of one of the three real samples, and deciding that an object neither carries the name
    nor watches for it takes interprocedural object facts the analysis does not have.
    """

    @unittest.expectedFailure
    def test_the_question_the_expansion_takes_away_was_answered_by_code(self):
        """
        Node prints `asked W` and then `asked console` for the program of
        `A_WITH_OBJECT_WATCHING_FOR_A_WRAPPER_NAME`: the body asks the scope object for both names.
        The deobfuscation expands the call, and the output asks only for `console`.
        """
        rows = A_WITH_OBJECT_WATCHING_FOR_A_WRAPPER_NAME
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


#: A self-disabling wrapper rebound through the global object under a name no fold can read, mapped
#: to what a host running the file as a classic script prints for it.
A_WRAPPER_REBOUND_UNDER_AN_UNREADABLE_KEY = {
    'function W() { W = function () {}; }\n'
    "globalThis[['W'].join('')] = function (a) { console.log('real', a); };\n"
    'W(1);\n': 'real 1\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnUnreadableKeyMayRebindAWrapperThroughTheGlobalObject(TestBase):
    """
    A write to the global object under a computed key names whatever the key evaluates to, and a key
    no fold reads names anything at all — including a wrapper the file declares at its top level,
    which under the script execution model is a property of that same object.

    The wrapper expansion accepts this, for the reason `TestAnUnreadableEvalMayRebindAWrapper`
    states: a reflective surface is what the real obfuscated files carry on the way in, and a pass
    gated on one never runs and never clears the surface that was gating it. A key a fold can read
    is not covered here — the write is then an ordinary one the model records against the binding,
    and the expansion refuses.
    """

    @unittest.expectedFailure
    def test_a_call_after_the_write_reaches_what_it_bound(self):
        """
        A host prints `real 1` for the program of `A_WRAPPER_REBOUND_UNDER_AN_UNREADABLE_KEY`: the
        key spells the wrapper's own name. The deobfuscation lowers the call to its argument and
        prints nothing.
        """
        rows = A_WRAPPER_REBOUND_UNDER_AN_UNREADABLE_KEY
        self.assertEqual(
            {source: before_and_after_in_a_host(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_the_key_is_still_unread(self):
        """
        The entry above pins the acceptance only while nothing reads the key: a fold that learns to
        answer `['W'].join('')` would flip it to an unexpected success by making the write visible,
        not by closing the acceptance. This holds the key unread — under it every statement folds
        away except the completion value the lowered call leaves, so any fold that starts reading
        the key shows here as a kept write.
        """
        source, = A_WRAPPER_REBOUND_UNDER_AN_UNREADABLE_KEY
        self.assertEqual(folded(source), '1;')


#: An accessor an IIFE answers, over a closure the answered function writes through a member of or
#: reads the identity of, mapped to what Node prints for it. Measured against
#: `refinery.lib.scripts.js.deobfuscation.iifeaccessor._is_safe_to_promote` answering False, which
#: leaves both programs standing whole.
A_CLOSURE_THE_PROMOTED_ACCESSOR_STOPS_SHARING = {
    'var acc = (function () {\n'
    '  var t = [0];\n'
    '  return function (i) { t[0] = t[0] + i; return t[0]; };\n'
    '})();\n'
    'console.log(acc(1), acc(1));\n': '1 2\n',
    'var acc = (function () {\n'
    "  var t = ['a'];\n"
    '  return function () { return t; };\n'
    '})();\n'
    'console.log(acc() === acc());\n': 'true\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAPromotedClosureIsStillOneObjectAcrossCalls(TestBase):
    """
    An IIFE answering a function is inlined by moving what the IIFE declared into the answered
    function's body, which builds those declarations afresh on every call. That is equivalent only
    where nothing carries a value or an identity from one call to the next, and `_is_safe_to_promote`
    asks it of a closure name written through a bare identifier and of nothing else: a closure
    written through a member keeps no count, and one whose identity is compared is a different object
    each time it is answered.

    Off the release gate deliberately: the accessor closures real obfuscators emit are
    memo-caches, whose rebuilt state recomputes the same values, so a promotion changes
    their speed and nothing an engine reports; state a program can watch accumulating
    across calls has had to be constructed.
    """

    @unittest.expectedFailure
    def test_a_closure_the_accessor_keeps_writing_or_comparing_is_not_promoted(self):
        """
        Node prints `1 2` for the first program of `A_CLOSURE_THE_PROMOTED_ACCESSOR_STOPS_SHARING`
        and `true` for the second. The deobfuscation folds them to `console.log(1, 1);` and
        `console.log(['a'] === ['a']);`, which print `1 1` and `false`.
        """
        rows = A_CLOSURE_THE_PROMOTED_ACCESSOR_STOPS_SHARING
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


#: A program whose parameter default runs a direct `eval` declaring a name the body reads, mapped
#: to the behavior an engine gives it.
A_DIRECT_EVAL_IN_A_DEFAULT_DECLARING_A_NAME = {
    'a var the eval declares, read by the body': Program(
        a_program("""
            var v = 1;
            function f(x = eval('var v = 2')) { return v; }
            console.log(f());
            """),
        prints('2'),
    ),
    'a var the eval declares, read by a later default': Program(
        a_program("""
            var v = 1;
            function f(a = eval('var v = 2'), b = v) { return b; }
            console.log(f());
            """),
        prints('2'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_DIRECT_EVAL_IN_A_DEFAULT_DECLARING_A_NAME)
class TestADirectEvalInADefaultDeclaresWhereItRuns(TestBase):
    """
    A direct `eval` in sloppy code declares a `var` in the variable scope it runs in, and the
    parameter list of a function carrying an expression is such a scope. The name it declares is
    therefore one the body reads instead of the outer one it would otherwise have read, and the
    program prints what the `eval` put there.

    The analysis resolves the body's read to the outer declaration and folds it, so the value the
    `eval` wrote is dropped. The root is not the parameter scope but the reach of a direct `eval`:
    `TestAParameterDefaultReadsPastTheBody` is about which scope a default reads from, and this one
    is about a scope whose contents no reading of the text gives.

    Off the release gate deliberately: no real file runs an `eval` in a parameter default to
    mint a binding, so the shape is this entry's own.
    """


#: A classic script reading one of its own top-level declarations through a name the file itself
#: installs on the global object, mapped to the behavior a host gives it. The installing statement is
#: what every row has in common: Node has no `window`, so a file meaning to read one has to put it
#: there, and a browser file that never installs one is already read correctly.
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
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_NAME_THE_FILE_INSTALLS_ON_THE_GLOBAL_OBJECT)
class TestANameTheFileInstallsOnTheGlobalObjectHoldsIt(TestBase):
    """
    A name given the global object holds it, and a read through the name is a read of a global —
    the law `test.lib.scripts.js.deobfuscation.test_a_name_holding_the_global_object` states. It is
    answered from the value the name is declared with, and a name the file only ever assigns is
    declared with none: the binding minted for `globalThis.window = globalThis` carries no
    declaration, so both value queries decline for it, the name is taken for one bound to something
    other than the object, and every global read through it is recorded nowhere.

    Declining is deliberate and its reason is an ordering one. The value would have to come from the
    write, and the writes made through the global object are recorded by the same walk that would ask
    — so what a read is admitted on would be how far that walk had got, which is not a fact about
    the program. Answering needs the writes established before any read is admitted, which is a
    change to how the model is built rather than to what it knows.

    The second row is the shape that made this worth having: `var w = window || {}` is how a file
    meant for a browser and for something else names the object once. It is read correctly wherever
    `window` is the host's own name, and wrongly only where the file installs that name itself.

    Off the release gate deliberately: a browser file relies on the host's own `window`,
    which is read correctly, and installing the alias oneself is a shape only cross-host
    shims come near.
    """


#: A declared name rebound to the global object by a plain write and then read through as a global,
#: mapped to what a host running the file as a classic script prints for it.
A_DECLARED_NAME_REBOUND_TO_THE_GLOBAL_OBJECT = {
    'a global is read through the rebound name': Program(
        a_program("""
            var secret = 'S';
            var g = {};
            g = globalThis;
            console.log(g.secret);
            """),
        prints('S'),
        Reading.SCRIPT,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_DECLARED_NAME_REBOUND_TO_THE_GLOBAL_OBJECT)
class TestADeclaredNameReboundToTheGlobalObjectHoldsIt(TestBase):
    """
    The sibling of `TestANameTheFileInstallsOnTheGlobalObjectHoldsIt` on a binding that has a
    declaration. Asked after the model is built, the recognizer answers correctly: the write's
    `globalThis` is among the name's values, and any value being the object admits it. But each
    member read is classified by the same walk that records that write, so whether `g.secret` is
    recorded as a read of the global depends on whether the walk reaches the read or the rebinding
    write first — which is not a fact about the program. The declaration deletes, and the read
    comes back `undefined`.

    The rule that closes it is the one the sibling entry names: establish every write before any
    member read is classified, a change to how the model is built rather than to what it knows.

    Off the release gate deliberately: a file names the global object once, at the declaration —
    initializing a name to junk and rebinding it to the object afterwards is this entry's own
    construction. The one-write spellings are the law
    `test.lib.scripts.js.deobfuscation.test_a_name_holding_the_global_object` holds green.
    """


#: A classic script handing the global object to a call from inside a function body, mapped to the
#: behavior a host gives it. Every row spells the object as the `this` of a function nothing calls as
#: a method, which §10.2.1.2 makes the global object for the duration of the call.
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
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(THE_GLOBAL_OBJECT_A_CALL_SUPPLIES_HANDED_ON)
class TestAReceiverACallSuppliesMayBeHandedOn(TestBase):
    """
    A function called with no receiver is given the global object as its `this`, and passing that on
    hands a second call every global the file declares. The references such a hand-over makes are
    recorded — `test.lib.scripts.js.deobfuscation.test_global_handed_to_a_call` states that law — but
    only for the spellings the text settles: an unshadowed alias, and the `this` a script's top level
    holds. Which receiver reaches a body is not decided anywhere, so a `this` written inside a
    function is not admitted, and a hand-over spelled with one is recorded nowhere.

    Admitting every `this` is measured, not assumed, and it is what this entry costs: a
    self-defending wrapper passes its own `this` to a call, and a run that took that for the global
    object leaves `test_obfuscated_fizzbuzz_01` at twenty times its deobfuscated size. Closing this
    needs the receiver a call supplies, which nothing answers today.

    Off the release gate deliberately: the spellings real files hand the object on with — a
    UMD factory's top-level `this`, `(function (g) {...})(this)`, a `.call(this)`
    wrapper — are all top-level and admitted already, and a bare-called function
    forwarding its own `this` has so far had to be constructed.
    """


class TestAnObjectPropertyFlagVariantIsStillRemoved(TestBase):
    """
    The tightened structural detector requires the run-once flag to be an identifier resolving to a
    closure binding, so a variant spelling the flag as an object property — `s.b ? ... : ...` with
    `s.b = false` — no longer matches, and its guard survives. The payload here is a console-member
    write, an anti-analysis marker real payloads carry, so the flag rule alone is what blocks the
    removal. The variant is hand-written: no witnessed emission spells the flag this way, which is
    why the recall loss is carried here rather than paid for with matcher
    surface. The rule that closes it extends the flag rule to a member path whose base resolves
    outside the factory and which is written false inside it.
    """

    @unittest.expectedFailure
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


#: A program whose only side effect between two observations runs inside a `toString` or `valueOf`
#: the conversion of a binary operand fires, mapped to the behavior Node gives it. The first two
#: rows drop the converting store outright; the third is the family's plainest witness, a global
#: written during the conversion and read after it; the last three keep the store alive through a
#: later use of its value, and the substitution moves the conversion past the read it was ordered
#: before.
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
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAConversionWithAnEffectIsNeitherDroppedNorMoved(TestBase):
    """
    Evaluating `'' + o` runs `o`'s own `toString`, and `o + 1` its `valueOf`, so a binary expression
    over a non-primitive operand runs program code the way a call does. The effect scan —
    `side_effect_free` and the model form over it — recurses into a binary expression's operands and
    asks nothing about the conversion itself, so an object whose converter carries a side effect is
    judged by its spelling: a plain variable read and a literal, both free. On that answer the sweep
    drops a dead store whose right-hand side converts (`var s = '' + o` goes, and `delete
    globalThis.X` inside the converter goes with it), and the inliner substitutes a single-use store
    forward past another statement (`console.log(s)` becomes `console.log('' + o)`, running the
    converter after the `X;` it was ordered before). Both rewrites need the same missing fact: a
    conversion of an operand the analysis cannot prove primitive may run arbitrary code, so it is
    droppable and movable only under the proof the call leaf already demands.

    A converting right-hand side that is kept for its effect is not enough to close the family: the
    third row's store is dropped by the same verdict, with no `delete` involved at all — a global
    written during the conversion simply never comes to exist.
    """

    @unittest.expectedFailure
    def test_each_program_still_observes_its_conversions_effect(self):
        rows = A_CONVERSION_WITH_AN_EFFECT_THE_SCAN_CANNOT_SEE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            {source: (answer, answer) for source, answer in rows.items()},
        )


#: Two programs whose read of a name nothing binds a pass relocates into a still-evaluated position,
#: mapped to the behavior Node gives each. The relocation keeps the read — the throw is not muted —
#: but moves it past an effect that ran before it: the IIFE inliner substitutes the argument `zzz`
#: into `b() + a` so the wrapper's own call runs before the throw, and the object fold moves the read
#: of `zzz` from the literal's construction to the later `o.q`, past the `console.log(1)` between. In
#: each the deobfuscation runs the intervening effect the original never reached.
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
    """
    A pass that relocates a read of a name nothing binds keeps the throw the read raises, but not its
    order against effects between the read's old and new positions. `is_safe_iife_inline` substitutes
    an argument the body reads once into the body without ordering that read against the body's own
    operations — its ordering discipline runs off the getter-half read leaf, which a bare-name
    `ReferenceError` does not trip — so a wrapper whose body calls another argument before reading this
    one runs that call before the throw. `JsObjectFold` moves a property value from the object literal
    to each access site, past whatever statements stand between, so the construction-time throw lands
    after them instead of before.

    Both keep the throw, so neither is a mute; the defect is the reordered effect. A correct
    implementation keeps the read where it stood relative to every observable effect, so each program
    behaves as it did. Closing it needs the ordering discipline to count a may-throw read (the IIFE
    path) and the fold to refuse relocating one past an intervening effect (the object-fold path) —
    neither a contained change to the drop-point guards that keep the read at all, which
    `test_unused.TestAReadOfANameNothingBindsSurvivesEveryDiscardingContext` pins.
    """

    @unittest.expectedFailure
    def test_a_relocated_may_throw_read_keeps_its_order(self):
        rows = A_RELOCATED_MAY_THROW_READ_KEEPS_ITS_ORDER
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            {source: (behavior, behavior) for source, behavior in rows.items()},
        )


def _a_chain_of_local_increments(n: int) -> str:
    lines = ['var v0 = 1;']
    for i in range(1, n):
        lines.append(F'var v{i} = v{i - 1} + 1;')
    lines.append('console.log(1);')
    return '\n'.join(lines) + '\n'


class TestADeepChainOfLocalsOverflowsTheRewriter(TestBase):
    """
    Inlining a chain of single-use locals substitutes each value into the next initializer, so the
    chain folds into one binary expression whose nesting depth is the chain's length. Every visitor
    in the pipeline walks the tree by recursing per node, and a tree four hundred operands deep
    exceeds the interpreter's recursion limit inside
    `refinery.lib.scripts.js.deobfuscation.simplify.JsSimplifications`, so the library run raises a
    `RecursionError` where a shorter chain folds to its final print. The `refinery.js` unit raises
    the interpreter's limit and catches the error, so a unit run does not die — it returns the
    input undeobfuscated, which is what the overflow costs there. The same chain written through
    implicit globals reduces at n = 1000, because the sweep deletes those stores without ever
    building the nested expression; the depth is made by the inliner, not by the input. The fix is
    an iterative walk, or folding during substitution so the intermediate tower never exists.
    """

    def test_a_chain_of_three_hundred_locals_folds_to_its_print(self):
        self.assertEqual('console.log(1);', deobfuscate_source(_a_chain_of_local_increments(300)))

    @unittest.expectedFailure
    def test_a_chain_of_four_hundred_locals_is_deobfuscated(self):
        self.assertEqual('console.log(1);', deobfuscate_source(_a_chain_of_local_increments(400)))


class TestACommentBehindTheLastStatementOfALiftedBlockIsKept(TestBase):
    """
    A block carries the comments standing behind its last statement, and a fold that lifts the
    statements out of the block — the body of `if (true)` — puts them where the block stood and
    throws the block away, comments included. No pass carries comments when it rebuilds a
    statement list, and the printer can write only what the tree holds.
    """

    @unittest.expectedFailure
    def test_the_comment_survives_the_fold_that_lifts_the_block(self):
        source = 'if (true) { console.log(1); /* c */ } console.log(2);'
        self.assertEqual(dropped_source_characters(source, deobfuscate_source(source)), '')


class TestAClassHeritageTheFileRefusesEndsWhereTheStatementDoes(TestBase):
    """
    Node refuses `class C extends { m(){} } g = 1;` with `SyntaxError: Unexpected identifier 'g'`.
    The heritage is the object literal, the class body is missing, and the statement the parser
    refuses runs to the end of its line: the assignment written behind it goes into the text
    kept for the class instead of being read as the statement it is. A refused clause body stops
    at the word that continues its statement, and a refused class stops nowhere before its line
    ends.
    """

    @unittest.expectedFailure
    def test_the_assignment_behind_the_refused_class_is_read_as_a_statement(self):
        source = 'class C extends { m(){} } g = 1;'
        tree = JsParser(source).parse()
        self.assertEqual(
            (unread_spans(tree), len(tree.body)),
            (['class C extends { m(){} }'], 2),
        )


class TestARestElementOffTheGlobalObjectIsNotAReflectionSurface(TestBase):
    """
    `const {...r} = globalThis` captures every own enumerable property of the global object into `r`,
    `eval` and `Function` among them, so `r[k](payload)` may be an indirect `eval` that runs in the
    global scope and rebinds any global. The reflection-surface test reads the object pattern's
    `JsProperty` entries and a rest element is not one, so the destructuring is cleared: the guard on
    the global `a` folds and its live branch is dropped. The computed member read `globalThis[k]` and
    the computed destructuring key `{[k]: e}` are both surfaces; the rest capture is the same
    value-read of the intrinsics under one more spelling and must be a surface too. The shape is
    elaborate, so its reach over real input is slim.
    """

    @unittest.expectedFailure
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


class TestASetterSwappedOntoObjectPrototypeIsNotSeen(TestBase):
    """
    Swapping a prototype onto `Object.prototype` installs an accessor on an object the global object
    inherits from, so a plain `globalThis.token = a` fires the setter the same way one swapped onto
    the global object's own `__proto__` does. The global-object question the pristine test asks refuses
    a `__proto__` write, and a `setPrototypeOf` hand-over, only where the base is the global object
    itself; a swap onto `Object.prototype` reaches the global object one link up the chain and is not
    seen, so the run reads as pristine and the second identical store is dropped, firing the setter
    once instead of twice. A swap onto a prototype the global object inherits is an exotic shape, so
    its reach over real input is slim.
    """

    @unittest.expectedFailure
    def test_a_store_survives_a_setter_swapped_onto_object_prototype(self):
        source = inspect.cleandoc(
            """
            Object.prototype.__proto__ = { __proto__: null, set token(v) {
              record(v);
            } };
            globalThis.token = a;
            globalThis.token = a;
            """
        )
        self.assertEqual(source, deobfuscate_source(source))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestPreserveScriptReturnDoesNotHoldASelfDefendingGuardCompletion(TestBase):
    """
    `preserve_script_return` holds the script's completion at every position but one: the value of a
    self-defending guard call. The guard `g = a(this, function(){ ... })` and its bare call `g()` are a
    single apparatus the deobfuscation removes whole; where that call is the script's completion the
    value falls from the guard's result to `undefined`. The removal is left ungated on purpose: sparing
    the call to hold its value keeps the whole self-defense apparatus alive and the pipeline that would
    take it apart never converges (a `DeobfuscationTimeout`), and a guard read for its value rather than
    armed for its effect is a shape no real payload carries. Node evaluates the original guard call to
    `0` and the fold to `undefined`.
    """

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

    @unittest.expectedFailure
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


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program({
    label: Program(source, prints('2'))
    for label, source in A_PROPERTY_READ_BELOW_A_BINDING_OF_ITS_OWN_NAME.items()
})
class TestAPropertyReadBelowABindingOfItsOwnName(TestBase):
    """
    A namespace property read from inside a function that binds the property's own name keeps that
    binding between the read and the declaration a flattening would emit, so the read belongs on the
    namespace object rather than rewritten: Node prints `2` for every program of the corpus and the
    deobfuscation prints `1`, the value of the binding below.

    Held back as a whole key this is not simply fixed. Obfuscators name the parameters of their
    decoder functions after the very properties the enclosing namespace flattens, and there the
    rewrite is sound: every position of the key sits inside the captured scope, the capturing
    binding is used nowhere else, and a write of the key precedes every read, so the binding below
    carries the value the property would. The string-array fold of a fold-heavy sample rides on that
    shape, which a hold-back would take apart. The fix is therefore a per-key question — whether
    every position is captured, whether the capturing binding is closed under the rewrite, and
    whether a write precedes every read — rather than the refusal this entry's programs ask for.

    Off the release gate deliberately: the miscompiled shape needs a read below a binding of its
    name that a live value distinguishes, and the decoy-parameter shape the obfuscators actually emit
    is the benign one above.
    """


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAReadBelowAHoistTheConflictWalkNeverSaw(TestBase):
    """
    A namespace's conflict walk prunes every function that binds the namespace's own name — a `M`
    inside a function with a parameter `M` refers to that parameter and not to the namespace — and
    the walk serves the key question with the same prune: a read of a key inside the pruned function
    is a read of an outer binding the flattening's own hoist captures, and the walk never counts it.
    The hoist of `M.A` therefore lands above the `A.X = 5` a sibling function carries, and that write
    reaches the hoisted function instead of the outer namespace `A` it resolved to.

    The sibling of `TestAPropertyReadBelowABindingOfItsOwnName`, one step further in: there the
    binding a read sits below is one the program already carries, and here it is one the flattening
    itself emits. Both come to the same per-key question — whether every position of the key is
    captured, and whether the capturing binding is closed under the rewrite — and to the same fix
    direction: the prune answers the namespace-name question, while the key question wants the
    resolution `refinery.lib.scripts.js.analysis.model.SemanticModel.is_shadowed` already answers
    for every occurrence the prune hides.

    The batch is why the corpus is two rows. Where the outer namespace flattens, the batch decides
    both plans against the entry tree, flattens the outer namespace too, and rewrites the read out
    from under the hoist — the batched pass answers the program correctly, and the sequential self,
    deciding the outer plan against the tree the inner plan already edited, declines it and keeps the
    capture. That divergence is held by the parity law of
    `test.lib.scripts.js.deobfuscation.test_namespaces`, whose row for it is skipped under the
    `--no-batch` differential along with every other property of the batch itself; this entry holds
    the row the pipeline cannot repair, whose outer namespace a bare read keeps.

    Off the release gate deliberately: the shape needs a nested namespace whose key carries an outer
    namespace's name, a sibling function binding the inner namespace's name, and a read of the outer
    name inside it, which has had to be constructed; the decoy-parameter shape the obfuscators emit is
    the benign one the sibling entry records.
    """

    @unittest.expectedFailure
    def test_the_write_below_the_hoist_reaches_the_outer_namespace(self):
        """
        Node prints `0 5` for the program of `A_READ_INSIDE_A_FUNCTION_BINDING_THE_NAMESPACES_NAME`
        whose outer namespace a bare read keeps: the write below the hoist reaches the outer
        namespace. The deobfuscation prints `0 0`, the write having reached the hoisted function
        instead.
        """
        source = A_READ_INSIDE_A_FUNCTION_BINDING_THE_NAMESPACES_NAME[
            'an outer namespace a bare read keeps'
        ]
        self.assertEqual(before_and_after(source), (prints('0 5'), prints('0 5')))


#: A program whose member array one scope assigns and a sibling scope reads, mapped to what Node
#: prints for it. The receiver is one the namespace flattener refuses — held in a parameter by the
#: first row, named by a global the file creates by the second — since a locally-declared empty
#: object carrying the shape is flattened whole before the pass reaches it. The key `X.Y` is the
#: same in every position of both programs, and nothing else writes it.
A_MEMBER_ARRAY_A_SIBLING_SCOPE_READS = {
    (
        'function outer(X) {\n'
        '  function f() { X.Y = [1, 2]; console.log(X.Y[0]); }\n'
        '  function g() { console.log(X.Y[1]); }\n'
        '  f();\n'
        '  g();\n'
        '}\n'
        'outer({});\n'
    ): ('1\n2\n', None),

    (
        'globalThis.X = {};\n'
        'function f() { X.Y = [1, 2]; console.log(X.Y[0]); }\n'
        'function g() { console.log(X.Y[1]); }\n'
        'f();\n'
        'g();\n'
    ): ('1\n2\n', None),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAMemberArrayASiblingScopeReadsIsStillWritten(TestBase):
    """
    A member array is a property of a receiver every scope in the file shares, so the question of
    whether a declaration of one is dead is a question about the whole file: an access a sibling
    scope holds keeps the assignment alive wherever it stands. `refinery.lib.scripts.js
    .deobfuscation.constants.JsConstantInlining` counts the `X.Y[...]` accesses of a key inside
    the subtree of the scope whose own statements hold the assignment — the same subtree whose
    walk decides the inlines — so an access in a sibling scope counts nowhere: it is never
    substituted, and it holds no count against the removal, which takes the assignment statement
    out and leaves the sibling reading a property nothing assigned.

    A correct implementation either counts the key's accesses over the whole file or asks the
    model which reads reach the receiver, the resolution the count's subtree restriction stands
    in for. What makes the shape reachable at all is a receiver outside the flattener's grasp,
    since a locally-declared empty object carrying it is flattened before the pass arrives and
    the member array never forms; a parameter and a file-created global are the two ways around
    that left standing here.

    Off the release gate deliberately: the miscompile needs the receiver outside the flattener's
    reach, the assignment and a surviving access in different function scopes, and the access
    declined by the fold's own index rules — a shape no sample family observed so far spells,
    the member arrays of real files being read by the same scope that holds them.
    """

    @unittest.expectedFailure
    def test_the_assignment_a_sibling_still_reads_is_kept(self):
        """
        Node prints `1` and then `2` for both programs of `A_MEMBER_ARRAY_A_SIBLING_SCOPE_READS`.
        Each deobfuscation prints `1` and then throws a `TypeError`, the sibling's read of `X.Y[1]`
        having survived an assignment that no longer stands.
        """
        rows = A_MEMBER_ARRAY_A_SIBLING_SCOPE_READS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            {source: (answer, answer) for source, answer in rows.items()},
        )


#: A packed access spliced into a `with` body whose object carries the accessor target's name, mapped
#: to the behavior Node gives each program. The read row asks the accessor and the write row runs
#: its setter, so what each prints is what the accessor did with the global the file declared,
#: printed beside the property the `with` object held all along.
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
@one_expected_failure_per_program(A_PACKED_ACCESS_A_WITH_OBJECT_SUPPLIES)
class TestAPackedAccessAWithObjectSuppliesStillGoesThroughTheProxy(TestBase):
    """
    The `Function` pack route resolves each packed `p.key` access through the accessor the call
    site hands it and splices the accessor's target in the access's place. The access it replaces
    is a member read on the pack's parameter, which no `with` object supplies, while the name it
    splices in is a bare one, which the `with` body around it resolves through the `with` object
    first: a property of the accessor target's name there supplies its own value where the accessor
    spelled a global the site resolves. A correct implementation declines the substitution for an
    access inside a dynamically-scoped region — the admission builds the model that answers where
    each spliced name lands — or asks which properties the `with` object can carry.

    Off the release gate deliberately: the packed code this pipeline reads carries its `with`
    objects for the scope confusion they buy, and they rebind the machinery names the packed code
    itself spells, never the accessor targets the substitution splices. Holding the landing to the
    question above declines the flagship pack rather than a diverging one, and the `with` object
    that supplies an accessor target's name has so far had to be constructed to reach.
    """
