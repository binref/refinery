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

An entry marked `test.lib.scripts.js.ledger.wontfix` instead is a defect that will not be fixed.
Only a shape made up for the defect reaches it: no obfuscator emits it and no program is written
that way. It is recorded to acknowledge the defect, it never runs, and nobody is to fix it or bend a
design around it; the marker says why no real input reaches the shape.

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
from test.lib.scripts.js.deobfuscation.test_stringarray import (
    A_PRESET_BESIDE_AN_ACCESSOR_CALL_NOTHING_CAN_ANSWER,
)
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
    one_expected_failure_per_program,
    dropped_source_characters,
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

from refinery.lib.scripts.js.analysis.environment import HostEnvironment
from refinery.lib.scripts.js.options import ExecutionModel
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


#: Programs storing into a name only the CommonJS reading binds where the store stands, a name the
#: CommonJS wrapper binds or the `var` a function declared in a block gives the function around
#: it, mapped to the behavior Node gives each as an ES module.
A_STORE_INTO_A_NAME_AN_ES_MODULE_LEAVES_UNBOUND = {
    'a store to exports nothing reads': Program(
        a_program("""
            try { exports = 1; } catch (e) { console.log(e.name); }
            console.log('end');
            """),
        prints('ReferenceError', 'end'),
        Reading.ES_MODULE,
    ),
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
@one_expected_failure_per_program(A_STORE_INTO_A_NAME_AN_ES_MODULE_LEAVES_UNBOUND)
class TestAStoreIntoANameAnEsModuleLeavesUnboundIsNotADeadStore(TestBase):
    """
    Under `-m` the file may be an ES module, which binds none of the names the CommonJS wrapper
    binds, gives a function declared in a block no `var` outside the block, and is strict code. A
    store into such a name lands on what the name means further out, or throws where nothing
    binds it. The model resolves the store to the binding the CommonJS reading has
    (`refinery.lib.scripts.js.analysis.model.Binding.may_be_absent`), and the sweep and the effect
    analysis read it as a store into that binding alone, which nothing reads: the store goes, and
    with it the throw or the write further out, as a store into no binding in strict code goes
    (`TestAWriteOnlyStrictCodeRefusesIsNotADeadStore`). The store and the binding it may not find
    have to be decided together here too.
    """


#: A file Node runs as an ES module because it declares a parameter of the CommonJS wrapper with
#: `const` at its top, mapped to the behavior Node gives it.
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
@one_expected_failure_per_program(A_FILE_A_LEXICAL_WRAPPER_NAME_MAKES_AN_ES_MODULE)
class TestTheDeclarationThatMakesAFileAnEsModuleStays(TestBase):
    """
    A file that may be CommonJS and declares a parameter of the CommonJS wrapper with `let`,
    `const` or `class` at its top is one Node runs as an ES module
    (`refinery.lib.scripts.js.options.file_kind`), and the analysis reads it as one. The passes
    that remove a declaration once nothing reads it remove this one too, and Node then runs the
    text left behind as a CommonJS file, which is sloppy code. The declaration has to stay the way
    an exported one does: the model has to report it as observed by the host, and every pass that
    removes a declaration has to ask.
    """


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


#: A program that writes a global property through `globalThis` and reads it back only through the
#: object a sloppy function called without a receiver returns as its `this`, mapped to what it
#: prints.
A_GLOBAL_PROPERTY_READ_THROUGH_A_RETURNED_THIS = {
    'globalThis.x = 1;\n'
    'var g = (function () { return this; })();\n'
    'console.log(g.x);\n': '1\n',
    'globalThis.x = 1;\n'
    'function f() { return this; }\n'
    'console.log(f().x);\n': '1\n',
}


class TestAGlobalObjectReturnedAsAFunctionsThisKeepsTheWritesReadThroughIt(TestBase):
    """
    A sloppy function called without a receiver runs with the global object as its `this`, so
    `(function () { return this; })()` hands the global object back, and a read through what it
    returns reads a global property without spelling any name the dead-global-property sweep of
    `refinery.lib.scripts.js.deobfuscation.unused.JsUnusedCodeRemoval` looks for. The sweep's
    escape test takes only the `this` of the top level and the names the model says hold the global
    object, and the model does not follow the object out of a call, so the write the read depends
    on is removed.

    Telling a plain call from a method call is a question about every invocation of the function,
    which the model does not answer yet, and taking every escaping `this` of a regular function for
    the global object would turn the sweep off wherever a method returns its receiver. The shape
    needs the write and the read to spell the global object differently; code that takes the global
    object this way writes through the name it reads through, and the sweep takes no write through
    such a name for a candidate.
    """

    @unittest.expectedFailure
    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_a_write_read_back_through_a_returned_this_is_kept(self):
        """
        Node prints `1` for both programs of `A_GLOBAL_PROPERTY_READ_THROUGH_A_RETURNED_THIS`: the
        function's `this` is the global object, which `globalThis.x = 1` wrote. Their
        deobfuscations drop that write and print `undefined`.
        """
        rows = A_GLOBAL_PROPERTY_READ_THROUGH_A_RETURNED_THIS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
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
A_FINDER_WHOSE_GLOBAL_RETURN_A_CAUGHT_THROW_SKIPS = inspect.cleandoc("""
    function g() { try { window.p; return self; } catch (e) {} }
    var x = g();
    console.log(typeof x);
""")

#: A finder whose one global-valued store to the name it returns reads `window` in a `try` block, so
#: where the host lacks `window` the store never happens and the finder returns `undefined`.
A_FINDER_RETURNING_A_NAME_WHOSE_GLOBAL_STORE_THREW = inspect.cleandoc("""
    function f() { var r; try { r = window; } catch (e) {} return r; }
    console.log(typeof f());
""")


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFinderWhoseGlobalReturnACaughtThrowSkipsIsKept(TestBase):
    """
    The finder fold recognizes a function as global-object-valued from its `return` expressions, but a
    `return` inside a `try` block need not be reached: a throw earlier in the block sends control to a
    catching handler that returns nothing, so the finder answers `undefined` in a host where the block
    throws. Folding its call to `globalThis` then substitutes a global object for `undefined` — a value
    divergence, not a dropped throw. Recognition would have to see that a global-valued return the
    finder relies on is not guaranteed to run. The same holds for a name the finder returns: one
    global-valued store to it marks it global everywhere, although a store that threw left it
    `undefined`.
    """

    @unittest.expectedFailure
    def test_a_finder_whose_global_return_is_skipped_by_a_caught_throw_is_kept(self):
        """
        Node prints `undefined` running the input (the caught throw skips `return self`); a correct
        deobfuscation keeps the call and prints the same, so the two agree.
        """
        source = A_FINDER_WHOSE_GLOBAL_RETURN_A_CAUGHT_THROW_SKIPS
        self.assertEqual(before_and_after(source), (('undefined\n', None), ('undefined\n', None)))

    @unittest.expectedFailure
    def test_a_finder_returning_a_name_whose_global_store_threw_is_kept(self):
        """
        Node prints `undefined`: reading `window` throws before `r` is written, so the finder
        returns the `undefined` `r` was declared with. A correct deobfuscation keeps the call and
        prints the same.
        """
        source = A_FINDER_RETURNING_A_NAME_WHOSE_GLOBAL_STORE_THREW
        self.assertEqual(before_and_after(source), (('undefined\n', None), ('undefined\n', None)))


#: Programs whose `try` block reads `window` before it stores `r`, so where the host lacks `window`
#: the store never runs, and whose `catch` clause then leaves by a throw or a `return` before the
#: `finally` reads `r`, mapped to what Node prints: the value `r` held before the store.
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
    """
    The control-flow graph builds the body of a `catch` clause with the `finally` as its handler, so
    a throw or a `return` out of the clause enters the `finally` as well. The `finally` is then not
    reached only from the end of the `try` block, where every store of the block has completed, and
    the constant inliner leaves the store the throw skipped out of what the `finally` reads. The
    builder is shared with PowerShell, whose traps route through the same method.
    """

    def test_the_finally_reads_the_value_from_before_the_store(self):
        rows = A_STORE_SKIPPED_BEFORE_A_CATCH_LEAVES_FOR_THE_FINALLY
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


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
#: class binding. A discarded call to such a function — a dead store — must keep the throw. The
#: function evaluator writes the read in place of the call where the reader reads nothing else, so
#: each such reader has a twin that reads `this` first, which keeps the call for the removal to see.
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
#: Reached directly, through an array right-hand side, and through a transitive callee. Each
#: reader reads `this` first, which keeps the call from being evaluated before the removal sees it.
A_DEAD_ASSIGNMENT_TO_A_DEAD_ZONE_READER = {
    'function f() { return this && q; }\nvar x;\nx = f();\nlet q = 1;\nconsole.log(2);\n': ('', 'ReferenceError'),
    'function f() { return this && q; }\nvar x;\nx = [f()];\nlet q = 1;\nconsole.log(2);\n': ('', 'ReferenceError'),
    'function g() { return this && q; }\nfunction f() { return g(); }\n'
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


#: A function given a `toString` of its own and then converted by a built-in that turns its
#: receiver's elements, its argument or a computed key into a string, mapped to what Node prints.
#: Each conversion runs the `toString` the program installed.
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
    'a string searched for it': Program(
        inspect.cleandoc('''
            function W(a) { return a + 1; }
            W.toString = function () { return "x"; };
            function f() { return 'axb'.indexOf(W); }
            console.log(f());
        '''),
        prints('1'),
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
@one_expected_failure_per_program(A_FUNCTION_A_BUILTIN_CONVERTS_THROUGH_ITS_OWN_TOSTRING)
class TestABuiltinConvertingAFunctionRunsItsOwnToString(TestBase):
    """
    `refinery.lib.scripts.js.deobfuscation.helpers.coerces_uninterceptably` refuses to convert a
    function the program may have given a `toString` of its own, but only where an operator, a
    template hole, `String` or `Number` converts it. The array methods, the string methods and the
    computed key of an object literal convert through `to_string` without asking, so they answer the
    text the function was written with. The fix is the chokepoint
    `TestABuiltinCoercingAnArgumentConsultsTheChainThatConvertsIt` names: the one question asked
    wherever a value is converted.
    """


#: Programs converting a function no code gives a conversion of its own, where a fold older than
#: the conversion question does not reach, mapped to what Node prints: the text the function was
#: written with.
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
@one_expected_failure_per_program(A_FUNCTION_HANDED_ON_WHERE_THE_FOLD_DOES_NOT_REACH)
class TestAFunctionHandedOnIsConvertedToItsWrittenTextWhereNoFoldReachesIt(TestBase):
    """
    Each program converts a function no code gives a conversion of its own, and the deobfuscation
    leaves the conversion standing, so it reads the text the deobfuscation printed rather than the
    text the function was written with. Each is wrong for a reason of its own, older than
    `refinery.lib.scripts.js.analysis.effects.EffectModel.function_conversion_untouched`:

    - a conversion at the top level of a script is never folded;
    - the interpreter does not read a top-level array from inside a function;
    - `setTimeout(W)` counts as a reflection surface although `W` is a function and not code;
    - a method of an object literal is not read once the object is handed on, since the object
      may be changed where it went;
    - namespace flattening rebuilds `NS.W = function (a) {…}` without its text and under the name
      `W`, so its conversion prints `function W(a) {…}`;
    - a function with rest parameters is never folded;
    - the `__extends` helper TypeScript emits writes `d.__proto__ = b` on a parameter and reads
      `Object.setPrototypeOf` as a value, so every function handed on in such a program is
      refused; knowing where that value goes needs interprocedural analysis.
    """


#: Programs that give a function handed on a conversion under a key known only at runtime, mapped
#: to what Node prints.
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
    """
    A key known only at runtime is no evidence that a program installs a conversion, so a function
    handed on beside a write under such a key converts to its written text, and the conversion the
    program installed is lost.
    """

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


#: Programs that give a function handed on a conversion through an installer reached in a way made
#: up for the scan, mapped to what Node prints.
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
    """
    The scan of conversion installs knows the installers by name and reads them where they are
    called or stored, so an installer reached another way installs a conversion the fold of a
    function handed on does not see.
    """

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


#: Programs that give `Function.prototype` a `toString` through a function literal, mapped to
#: what Node prints.
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
    """
    `Function.prototype` given a `toString` through the prototype or `__proto__` of a function
    literal changes every conversion of a function, and the prototype chain is read as untouched.
    """

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

#: Programs that give a conversion method to a value the scan of conversion installs reads as any
#: function, and convert a function they hand on, mapped to what Node prints: the text the function
#: was written with.
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
@one_expected_failure_per_program(A_FUNCTION_HANDED_ON_BESIDE_A_CONVERSION_ON_A_VALUE_READ_AS_ANY_FUNCTION)
class TestAFunctionHandedOnConvertsToItsWrittenTextBesideAConversionOnAValueReadAsAnyFunction(TestBase):
    """
    `refinery.lib.scripts.js.analysis.conversions.ConversionInstalls` reads `X.prototype` once a
    program replaces it, and the result of `bind`, as values that may hold any function, so a
    conversion method given to one of them is evidence about every function. The conversion of a
    function the program hands on then stays, and runs on the text the deobfuscation printed. The
    fix reads a replaced prototype through the values written to it, and a bound copy as a function
    no literal is.
    """


#: Programs that call or convert a top-level function of a classic script after a write to the
#: global object under a key a helper is handed replaced it, mapped to what a host prints.
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
@one_expected_failure_per_program(A_NAME_A_GLOBAL_WRITE_UNDER_A_RUNTIME_KEY_REPLACES)
class TestANameAGlobalWriteUnderARuntimeKeyReplacesIsNotReadAsItsDeclaration(TestBase):
    """
    In a classic script a top-level name is a property of the global object, and
    `globalThis[name] = value` under a key known only at runtime may replace it. The interpreter
    still reads the name as the function its declaration gives it, so a call through it folds to
    what the declared function returns. The conversion of such a function used to be refused for
    the write and now folds to its written text the same way. The fix is in the interpreter's read
    of a name: one that such a write may replace
    (`refinery.lib.scripts.js.analysis.model.SemanticModel.opaque_global_write_replacement_sites`)
    holds its declared value only where no such write can run before the read.
    """


#: A program that hands a function on beside an installer used as the tag of a template, mapped to
#: what Node prints: the text the function was written with.
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
    """
    The scan of conversion installs reads an installer used as a tag as an installer read as a
    value, which may install on any function, so the conversion of a function handed on stays and
    runs on the text the deobfuscation printed.
    """

    @wontfix('no program calls an installer as the tag of a template, which passes it the strings of the template')
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        rows = A_FUNCTION_HANDED_ON_BESIDE_AN_INSTALLER_USED_AS_A_TAG
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


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


#: Programs that reach an intrinsic prototype through a name the file bound the receiver to, rather
#: than through the literal itself, mapped to what Node prints for each. Reading `__proto__` off a
#: binding, and handing that binding to a `getPrototypeOf` the file also bound, are the same gadget
#: written one indirection further out: what the spelling reaches is decided by the value the
#: binding holds, which the syntax at the write does not show. The last two reach `Array.prototype`
#: through a parameter, which holds the array its call hands it: one replaces `join`, which a call
#: on an array literal then runs as the built-in, and one replaces `slice` with a method writing its
#: receiver, which an array the program reads only through `slice` is then taken to be safe from.
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
    """
    `refinery.lib.scripts.js.deobfuscation.protospelling` writes each spelling that reaches an
    intrinsic prototype out as the name it reaches, which is what puts the write in front of every
    check already looking for one. It reads the receiver from the syntax, so a receiver held in a
    binding is one it declines: `test_a_receiver_the_syntax_does_not_decide_is_left_alone` pins that
    refusal, and these are what the refusal costs.

    Closing it needs the value the binding holds rather than new machinery — the model already
    answers what a binding is assigned, and the pass would consult it where the receiver is a name.
    The same is true of the callee: `g` is `Object.getPrototypeOf` and the file said so. A
    parameter holds what the calls of its function hand it, which the model answers where it sees
    every call.

    Off the release gate deliberately: the one prototype write real obfuscation spells is the
    literal `X.prototype.m = f`, which is read; a write that reaches the prototype through
    a binding has so far had to be constructed to be seen.
    """

    @unittest.expectedFailure
    def test_a_prototype_reached_through_a_binding_answers_the_read(self):
        """
        Node prints `9`, `9`, `X` and `9` for the programs of
        `A_PROTOTYPE_REACHED_THROUGH_A_BINDING`, each of which reaches an intrinsic prototype
        through a name rather than through a literal. The first two deobfuscations print
        `undefined`, and come back having replaced the read with a variable nothing writes; the
        third prints `1-2` and the fourth `1`, each answering as if `Array.prototype` were unwritten.
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
    r'(function (O) { O.prototype[Symbol.toPrimitive] = function () { return "\n"; }; })(Object);' '\n'
    + checked():
        'tampered\nran\n',
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
        Node prints `9`, `9`, `false`, `9`, `9`, and `tampered` before `ran`, for the six programs
        of `A_PROTOTYPE_HANDED_TO_SOMETHING_THAT_WRITES_IT`. Each deobfuscation answers as if the
        call it was handed to had not written it; the last folds a line-break check that the
        conversion the call installed makes trip.
        """
        rows = A_PROTOTYPE_HANDED_TO_SOMETHING_THAT_WRITES_IT
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


#: A program that reaches `Object.prototype` through a method returning it, and writes it through
#: the call's result, mapped to what Node prints.
A_PROTOTYPE_A_METHOD_RETURNS = {
    'var A = {f: function () { return Object.prototype; }};'
    ' var P = A.f(); P.p = 1; var B = {q: 2}; console.log(B.p);':
        '1\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAPrototypeAMethodReturnsIsStillWrittenByItsCaller(TestBase):
    """
    The prototype leaves the method the way `TestAPrototypeHandedToAWriterIsStillWritten` has it
    leave through an argument: `return` is an escape, which the intrinsic-write scan records against
    the keys of `Object` and not against the name. The caller then holds it in a name whose value is
    a call result the scan does not follow, so the write through that name is attributed to nothing,
    and the chain questions read `Object.prototype` as unwritten. The fix is the one that entry
    names: follow the escaped value to its writes, here from the `return` to the call's result.
    """

    @unittest.expectedFailure
    def test_a_prototype_a_method_returns_answers_the_read(self):
        """
        Node prints `1` for the program of `A_PROTOTYPE_A_METHOD_RETURNS`; its deobfuscation folds
        the inherited read to `undefined`.
        """
        rows = A_PROTOTYPE_A_METHOD_RETURNS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


#: A program that writes `Object.prototype` through the property of the global object that holds
#: `Object`, spelled with a name Node gives the global object, mapped to what Node prints.
A_PROTOTYPE_WRITTEN_THROUGH_THE_GLOBAL_OBJECT = {
    'global.Object.prototype.k = 1; var B = {x: 1}; console.log(B.k);':
        '1\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAPrototypeWrittenThroughTheGlobalObjectIsStillWritten(TestBase):
    """
    The intrinsic-write scan attributes a write through a member chain to the name at the chain's
    foot, which for `global.Object.prototype.k = 1` is `global`, and `Object` is never named. The
    spelling `globalThis.Object` is respelled as `Object` before the scan reads it, which a name
    the run does not guarantee to be the global object, such as `global`, `window` or `self`, is
    not; the chain questions then read `Object.prototype` as unwritten. The fix: where the foot of a
    written chain may be the global object
    (`refinery.lib.scripts.js.analysis.model.SemanticModel.may_be_the_global_object`), the scan
    attributes the write to the property read off it, as it would to that name spelled bare.
    """

    @unittest.expectedFailure
    def test_a_prototype_written_through_the_global_object_answers_the_read(self):
        """
        Node prints `1` for the program of `A_PROTOTYPE_WRITTEN_THROUGH_THE_GLOBAL_OBJECT`; its
        deobfuscation folds the inherited read to `undefined`.
        """
        rows = A_PROTOTYPE_WRITTEN_THROUGH_THE_GLOBAL_OBJECT
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


#: A program that installs a getter where a built-in keeps one of its methods and reads the method
#: bare, mapped to what Node prints.
AN_ACCESSOR_ON_A_BUILT_IN_READ_BARE = {
    'Object.defineProperty(Math, "floor", {get: function () { console.log("ran"); return Math.round; }});'
    ' Math.floor; console.log(1);':
        'ran\n1\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnAccessorInstalledOnABuiltInRunsWhereItIsRead(TestBase):
    """
    The effect model trusts a built-in's value under one program-wide flag
    (`refinery.lib.scripts.js.analysis.effects._intrinsics_pristine`) that looks for assignments to
    the built-ins and to their properties, and not for descriptors installed on them. A read of a
    property the program has turned into a getter is then taken for one that runs nothing, and the
    bare read is dropped together with what the getter does.
    """

    @wontfix(
        'programs and obfuscators replace a built-in method by assigning it, which the flag sees; '
        'none installs a getter on a built-in and reads the method bare for what the getter does'
    )
    def test_a_getter_installed_on_a_built_in_runs_where_it_is_read(self):
        """
        Node prints `ran` and then `1` for the program of `AN_ACCESSOR_ON_A_BUILT_IN_READ_BARE`;
        its deobfuscation drops the read and prints only `1`.
        """
        rows = AN_ACCESSOR_ON_A_BUILT_IN_READ_BARE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


#: A function flattened into a generator whose `with` statement reads its scope object, and whose
#: code reads `label` bare, as the obfuscator leaves every name the function does not declare.
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

#: A function flattened the same way that puts `label` on every object through a copy of
#: `Object.prototype` it keeps in its scope object, as `var proto = Object.prototype` becomes once the
#: function's locals are slots of that object.
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


#: The reader and then the writer, called in the other order, mapped to what Node prints: the scope
#: object finds `label` on its prototype, which the writer has put it on by the time the reader runs,
#: before the `with` statement would look past the object to the global.
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
    """
    Generator unflattening removes the reader's `with` statement only where no name its code reads
    bare is one a plain object may inherit, since inside the statement the scope object finds such a
    name before the global (`JsStateMachineUnflattening._provably_absent`). That answer comes from
    the writes the effect model sees to `Object.prototype`, and the writer's is made through a copy
    of the prototype kept in its scope object. The write scan follows a value only while a name holds
    it, and it trusts `Object` wherever it escapes (`ESCAPE_RECORDED_ROOTS` leaves it out), so it
    sees the write only once the writer is recovered and the copy has become a local. A reader the
    pass reaches first is recovered on the answer from before that, its `label` turns into the
    global, and the program prints `the global label`. A correct implementation declines the reader
    while a copy of `Object.prototype` the scan cannot follow may write `label`; the root cause is
    the one `TestAPrototypeHandedToAWriterIsStillWritten` pins for a prototype handed to a call.
    """

    @wontfix(
        'the obfuscator flattens the top level as well: a global the program declares becomes a slot '
        'the reader reads under a generated key, and a global it leaves bare is read inside the '
        'machine wrapping the whole program, whose recovery shows the write before the reader is '
        'decided; every obfuscation of this program by 2.0.0, 2.0.1 and 2.1.3 deobfuscates to one '
        'that prints what its input prints'
    )
    def test_a_reader_placed_before_the_writer_reads_the_inherited_name(self):
        """
        Node prints `the label every object inherits` for the program of
        `A_NAME_PUT_ON_EVERY_OBJECT_BY_A_LATER_FLATTENED_WRITER`. Its deobfuscation recovers the
        reader and prints `the global label`.
        """
        rows = A_NAME_PUT_ON_EVERY_OBJECT_BY_A_LATER_FLATTENED_WRITER
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


#: The programs of the same name in the file-kind tests, read as classic scripts.
A_DIRECT_EVAL_IN_A_DEFAULT_DECLARING_A_NAME = as_classic_scripts(
    the_file_kind.A_DIRECT_EVAL_IN_A_DEFAULT_DECLARING_A_NAME
)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_DIRECT_EVAL_IN_A_DEFAULT_DECLARING_A_NAME)
class TestADirectEvalInADefaultDeclaresWhereItRuns(TestBase):
    """
    A direct `eval` in sloppy code declares a `var` in the variable scope it runs in, and the
    parameter list of a function carrying an expression is such a scope. The name it declares is
    therefore one the body reads instead of the outer one it would otherwise have read, and the
    program prints what the `eval` put there.

    The analysis resolves the body's read to the outer declaration and folds it where that is a
    top-level variable of a classic script, so the value the `eval` wrote is dropped; a module's
    own variables are within the reach of every direct `eval` of the file, and stay. The root is
    not the parameter scope but the reach of a direct `eval`:
    `TestAParameterDefaultReadsPastTheBody` is about which scope a default reads from, and this one
    is about a scope whose contents no reading of the text gives.

    Off the release gate deliberately: no real file runs an `eval` in a parameter default to
    mint a binding, so the shape is this entry's own.
    """


#: The programs of the same name in the file-kind tests, read as classic scripts.
A_DIRECT_EVAL_IN_A_BODY_DECLARING_A_NAME = as_classic_scripts(
    the_file_kind.A_DIRECT_EVAL_IN_A_BODY_DECLARING_A_NAME
)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_DIRECT_EVAL_IN_A_BODY_DECLARING_A_NAME)
class TestADirectEvalInABodyDeclaresWhereItRuns(TestBase):
    """
    The defect of `TestADirectEvalInADefaultDeclaresWhereItRuns` without the parameter default: a
    direct `eval` in sloppy code declares a `var` in the variable scope of the function it runs in,
    so a read of that name after it finds what the `eval` put there, not the outer variable.
    Constant inlining resolves the read to the outer declaration and folds the value written there.
    The question it has to ask is one the model answers
    (`refinery.lib.scripts.js.analysis.model.SemanticModel.direct_eval_declares_below`), and only a
    top-level variable of a classic script is folded this way: a local of an enclosing function and
    a top-level variable of a module are refused because a direct `eval` reaches them. A program
    running code it is handed is possible in real input; the defect needs that code to declare a
    name the function also reads from outside.
    """


#: The programs of the same name in the file-kind tests, read as classic scripts.
A_VARIABLE_AN_UNREADABLE_EVAL_ASSIGNS_READ_BY_A_FUNCTION = as_classic_scripts(
    the_file_kind.A_VARIABLE_AN_UNREADABLE_EVAL_ASSIGNS_READ_BY_A_FUNCTION
)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_VARIABLE_AN_UNREADABLE_EVAL_ASSIGNS_READ_BY_A_FUNCTION)
class TestAVariableAnUnreadableEvalMayAssignIsNotWrittenIntoAFunctionReadingIt(TestBase):
    """
    A direct `eval` of a string nothing can fold may assign any variable it can see. Constant
    inlining orders a read in the scope of the variable against such an `eval` and keeps the read
    standing after it, but writes the value into a function reading the variable when the value
    runs before every call of that function
    (`refinery.lib.scripts.js.analysis.dominance.DominanceModel.runs_before_every_invocation`),
    without asking whether an `eval` runs between the two. The base91 pass then keeps the call of
    an accessor whose long string was written into it, and the call slices the old string. Only a
    top-level variable of a classic script is written in: a module's own variables are within the
    reach of every direct `eval` of the file, and no value of theirs is. A program running code it
    is handed is possible in real input; the defect needs that code to assign a variable of the
    file that holds one value otherwise.
    """


#: A classic script reaching one of its own top-level declarations through a name the file itself
#: installs on the global object — by a write through the object, or by assigning a name it never
#: declares — mapped to the behavior a host gives it. The installing statement is what every row has
#: in common: Node has no `window`, so a file meaning to read one has to put it there, and a browser
#: file that never installs one is already read correctly.
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
@one_expected_failure_per_program(A_NAME_THE_FILE_INSTALLS_ON_THE_GLOBAL_OBJECT)
class TestANameTheFileInstallsOnTheGlobalObjectHoldsIt(TestBase):
    """
    A name given the global object holds it, and a read through the name is a read of a global —
    the law `test.lib.scripts.js.deobfuscation.test_a_name_holding_the_global_object` states. It is
    answered from the values the name is declared with and assigned, and a name the file never
    declares has none: neither the binding minted for `globalThis.window = globalThis` nor the
    implicit global `w = globalThis` creates carries a declaration, so both value queries decline
    for them, the name is taken for one bound to something other than the object, and every global
    reference through it is recorded nowhere.

    The names holding the global object are found once, from the values written to names, before any
    member access is classified, because which member accesses reach a global depends on which names
    hold the object. An installing write through the object is a member access, so its value is not
    among those values. That order does not forbid reading it: which global `B.n = V` writes is
    named by `n`, and whether it writes one only grows as more names are found to hold the object.
    The rules that close it: such a write whose base and value both hold the object makes `n` hold
    it too, one more rule of the fixpoint `refinery.lib.scripts.js.analysis.model.SemanticModel`
    finds the holders by, and that fixpoint reads the values an undeclared name is assigned by name.

    The second row is the shape that made this worth having: `var w = window || {}` is how a file
    meant for a browser and for something else names the object once. It is read correctly wherever
    `window` is the host's own name, and wrongly only where the file installs that name itself.

    Off the release gate deliberately: a browser file relies on the host's own `window`,
    which is read correctly, and installing the alias oneself is a shape only cross-host
    shims come near.
    """


#: A classic script reaching one of its own top-level variables through a name holding the global
#: object, from inside a function it calls, mapped to the behavior a host gives it.
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
    'a read after a write by name in a function called twice': Program(
        a_program("""
            var g;
            var w = global || {};
            function f() { g = 1; console.log(w.g); }
            f();
            f();
            """),
        prints('1', '1'),
        Reading.SCRIPT,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_GLOBAL_REACHED_INSIDE_A_CALL_THROUGH_A_NAME_HOLDING_THE_GLOBAL_OBJECT)
class TestAGlobalReachedInsideACallThroughANameHoldingTheGlobalObjectIsReachedThere(TestBase):
    """
    The model records `w.g = 2` as a write of `g` and `w.g` as a read of it, but whether a variable
    is reached through the global object is decided a second time, from how the base of each
    recorded member access is spelled: `w` is not a spelling of the global object, so `g` is taken
    for a variable no member access reaches. The effect summary of a function writing `w.g` does
    not list `g` either, so a read after the call is folded to the value the declaration spelled;
    and `g = 1` inside `f` is removed as a store no other code reads. The same write made at the
    top level is read correctly; the law
    `test.lib.scripts.js.deobfuscation.test_a_name_holding_the_global_object` holds it.

    The rule that closes it: the model marks each reference it records through the global object as
    such, and every later question reads that mark instead of the spelling.
    """


#: A classic script reading one of its own top-level declarations through the global object beside
#: the reads it makes by name, mapped to the behavior a host gives it.
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
@one_expected_failure_per_program(A_DECLARATION_ALSO_READ_THROUGH_THE_GLOBAL_OBJECT)
class TestADeclarationAlsoReadThroughTheGlobalObjectIsKept(TestBase):
    """
    The model records a read through the global object against the declaration it reaches, and that
    record keeps the declaration of a file that reads it there and nowhere else — the law
    `test.lib.scripts.js.deobfuscation.test_a_name_holding_the_global_object` holds it. Two passes
    count only the identifiers spelled with the name: constant inlining replaces the reads by name
    and then removes the declaration, and namespace flattening turns the object into one variable
    per key. The read through the object is then a read of a property nothing defines any more.

    The rule that closes it: a pass removing or splitting a declaration counts every reference the
    model records for it, the ones through the global object included.
    """


#: A classic script calling one of its own functions through the global object, mapped to the
#: behavior a host gives it.
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
    """
    `globalThis.tick()` runs the file's own `tick`. The effect model takes it for a call by name
    when it decides that `tick` does not escape, but resolves which function a call runs only for a
    callee spelled as a name, so nothing treats the call as running `tick`, and the value `tick`
    writes is folded across it.
    """

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


#: A classic script naming the global object once with the test a file meant for several hosts
#: writes, and writing one of its own top-level variables through that name, mapped to the behavior
#: a host gives it.
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
@one_expected_failure_per_program(A_NAME_GIVEN_THE_GLOBAL_OBJECT_BY_A_HOST_TEST)
class TestANameGivenTheGlobalObjectByAHostTestHoldsIt(TestBase):
    """
    A name holds the global object when a value it is given is spelled as the object, or is an `||`
    whose left is, which covers `var w = window || {}`. A file meant for several hosts tests first
    and spells the object in a branch: the arms of a conditional and the right of an `&&` are not
    read, so the name is taken for one holding something else and the write through it is recorded
    nowhere. A library's wrapper handed the conditional as an argument has the same blind spot in
    the parameter that receives it.

    The rule that closes it: a value is the object when any value it may evaluate to is — either arm
    of a conditional, the right of an `&&`, either side of `||` and `??`, the last of a sequence —
    the may-reading `refinery.lib.scripts.js.analysis.intrinsics` already makes of a name's value.
    """


#: A classic script patching a built-in through a conditional written in place of the object, mapped
#: to the behavior a host gives it.
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
    """
    The scan for writes to built-ins finds the object a member write patches from the name its base
    is spelled with, and a conditional written in place of that name names none, so the patch is not
    seen and `Math.floor(1.5)` is folded to the built-in's answer. The same patch made through a
    name holding the conditional is seen.
    """

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


#: A classic script handing the global object on from inside a function body — to a call or to a
#: name — mapped to the behavior a host gives it. Every row spells the object as the `this` of a
#: function nothing calls as a method, which §10.2.1.2 makes the global object for the duration of
#: the call.
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
@one_expected_failure_per_program(THE_GLOBAL_OBJECT_A_CALL_SUPPLIES_HANDED_ON)
class TestAReceiverACallSuppliesMayBeHandedOn(TestBase):
    """
    A function called with no receiver is given the global object as its `this`, and passing that on
    hands a second call every global the file declares. The references such a hand-over makes are
    recorded — `test.lib.scripts.js.deobfuscation.test_global_handed_to_a_call` states that law — but
    only for the spellings the text settles: an unshadowed alias, and the `this` a script's top level
    holds. Which receiver reaches a body is not decided anywhere, so a `this` written inside a
    function is not admitted: a hand-over spelled with one is recorded nowhere, and a name given one
    is not taken for a name holding the global object.

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


#: A packed access spliced into a `with` body whose object carries the accessor target's name,
#: mapped to the behavior Node gives each program. The read row asks the accessor and the write row
#: runs its setter, so what each prints is what the accessor did with the global the file declared,
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
    access inside a dynamically-scoped region, or asks which properties the `with` object can
    carry.

    Off the release gate deliberately: the packed code this pipeline reads carries its `with`
    objects for the scope confusion they buy, and they rebind the machinery names the packed code
    itself spells, never the accessor targets the substitution splices. Holding the landing to the
    question above declines the flagship pack rather than a diverging one, and the `with` object
    that supplies an accessor target's name has so far had to be constructed to reach.
    """


#: A classic script that declares a name the global object holds as a read-only property and stores
#: a value in it, mapped to what the host prints: the store is ignored in sloppy code, and the name
#: still reads what the global object holds.
A_STORE_A_READ_ONLY_GLOBAL_IGNORES = {
    a_program("""
        var NaN = 5;
        console.log(NaN);
        """): 'NaN\n',
}


class TestAScriptLevelVarSharingAReadOnlyGlobalHoldsNoStoredValue(TestBase):
    """
    A script-level `var` names a property of the global object, and where that property is
    read-only, sloppy code ignores the store a declaration or an assignment makes to it. The
    language makes `NaN`, `Infinity` and `undefined` read-only, and a browser does the same for
    `window`, `document`, `top` and many more names. The deobfuscation folds the read to the stored
    value. A correct one keeps the read, or folds it to what the global object holds where the host
    is known.
    """

    @unittest.expectedFailure
    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_a_read_after_a_store_a_language_global_ignores_prints_the_global(self):
        rows = A_STORE_A_READ_ONLY_GLOBAL_IGNORES
        self.assertEqual(
            {source: before_and_after_in_a_host(source) for source in rows},
            each_program_still_prints(rows),
        )

    @unittest.expectedFailure
    def test_a_read_after_a_store_a_browser_global_ignores_is_kept(self):
        """
        Node has no read-only `top`, so the text of the output holds this row: in a browser the
        read prints the window, not `5`.
        """
        source = a_program("""
            var top = 5;
            console.log(top);
            """)
        self.assertIn('console.log(top)', folded(source))


#: Programs that give a local object the key `k` by a write the `in` fold does not count, mapped to
#: what Node prints: every one of them prints `true`.
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
    """
    The fold of `'k' in X` over a local object literal reads the keys `X` holds off the plain
    assignments `X.k = v` and nothing else, so a key written through another name for the object,
    through a destructuring or `for-in` target, through an accessor install, or through a method
    that returns the object itself, is answered absent.
    """

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


#: Programs that take the prototype away from a local object before asking for a key only the
#: prototype supplies, mapped to what Node prints: `false` for both.
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
    """
    The fold of `'k' in X` answers `true` for a key `Object.prototype` supplies before it asks
    whether `X` still inherits from it, and a prototype replaced through another name or through
    `Object.setPrototypeOf` is not seen.
    """

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


#: Programs asking a function that has no `prototype` property for one, mapped to what Node prints:
#: an arrow function and an async function have none.
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
    """
    The fold of `'prototype' in f` answers `true` for every function, while an arrow function and an
    async function carry no `prototype` property at all.
    """

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


#: Programs that write `Object.prototype` through a route the scan of written intrinsics does not
#: see, mapped to what Node prints. The last one installs a getter there through a function
#: parameter and then reads a key of a namespace object, which runs the getter with the namespace
#: as `this` before `a` exists.
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

#: The program of `AN_OBJECT_PROTOTYPE_WRITTEN_INDIRECTLY` whose getter calls a method before `a`
#: exists, which throws `ReferenceError`.
A_GETTER_INSTALLED_THROUGH_A_PARAMETER = a_program("""
    var P = Object.prototype;
    function install(o) { o.__defineGetter__('k', function () { return this.g(); }); }
    install(P);
    var NS = {h: 1};
    NS.g = function () { return a[0]; };
    console.log(NS.k);
    const a = [7, 8];
    """)

#: The program of `A_GETTER_INSTALLED_THROUGH_A_PARAMETER` with the getter installed on
#: `Object.prototype` through a path that starts elsewhere than at `Object`, keyed by that start
#: and mapped to the behavior an engine gives it.
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
    """
    The scan of what a program writes on the intrinsics sees a write whose target spells the
    prototype, or a local the prototype was stored in, and a descriptor install named by its
    method. `Object.assign` and `Reflect.set` write `Object.prototype` through an argument, and a
    method call on a parameter holding it installs a getter no assignment spells, so the scan
    reports the prototype unwritten. The `in` fold then answers from the object alone, and the
    ordering of a namespace method misses the getter that calls it.
    """

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
    """
    The scan of what a program writes on the intrinsics credits a prototype write only to the name
    the written chain starts at, so a getter installed on `Object.prototype` through another
    object, its constructor, or an array is missed. The ordering of a namespace method then misses
    the getter that calls it before `a` exists, and the deobfuscation writes `7` into `NS.g`.
    """

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


#: Programs that mutate a local object through a built-in method called on it, mapped to what Node
#: prints: `valueOf` returns the object itself, and `__defineGetter__` replaces the property.
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
    """
    Object folding reads a property of a local object literal off the literal, treating a method
    call on the object as unable to change it. `valueOf` hands the object itself back, and
    `__defineGetter__` replaces the property with an accessor, so the value read later is not the
    literal's.
    """

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


#: Programs that write `Object.prototype` through `Object` held where the models do not follow it,
#: mapped to what Node prints: an element of an array, and a thrown value.
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
    """
    The scan of what a program writes on the intrinsics follows `Object` through the names and the
    arguments that hold it, and not through an element of an array or a thrown value. The write to
    its prototype is not seen, and object folding reads the key `B` lacks as absent.
    """

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


#: Classic scripts that write one of their top-level variables through the global object held where
#: the models do not follow it, mapped to what a host running them prints: a property of an object
#: no fold removes, a default parameter, and an element a destructuring takes.
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
    """
    The semantic model finds the names holding the global object among the variables it is given to
    and the parameters a call hands it to, and not among the properties of an object, the defaults
    of parameters, or the targets of a destructuring. The write through such a name is recorded
    nowhere, and object folding reads `C.x` off the literal.
    """

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


#: Programs that install a key on every object through a method whose name an object holds, and read
#: that key off an object of their own, mapped to what Node prints: the reading object declared
#: before the one holding the name, and declared in a function nested in its scope. An obfuscator
#: stores the names a program spells in such objects, and the program itself is arbitrary.
A_KEY_ANOTHER_OBJECT_READS_AFTER_A_COPY_INSTALLED_IT = {
    a_program("""
        var B = {x: 1};
        var A = {k: "defineProperty"};
        Object[A.k](Object.prototype, "q", {value: 1});
        console.log(B.q);
        """): '1\n',
    a_program("""
        var A = {k: "defineProperty"};
        Object[A.k](Object.prototype, "q", {value: 1});
        function t() { var B = {y: 1}; return B.q; }
        console.log(t());
        """): '1\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAKeyAnotherObjectReadsAfterACopyInstalledItIsFound(TestBase):
    """
    Object folding decides one object at a time, and reads a key an object lacks as absent where
    the models see no install of it. The install `Object[A.k](...)` becomes readable once the copy
    of `"defineProperty"` is made, so an object decided before `A`, declared earlier or in a nested
    function, reads the key as absent.

    The rule that closes it: the pass decides the keys objects inherit after it made the copies of
    every object, on models renewed after them.
    """

    @unittest.expectedFailure
    def test_the_key_is_found(self):
        rows = A_KEY_ANOTHER_OBJECT_READS_AFTER_A_COPY_INSTALLED_IT
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


#: Classic scripts that read a top-level object through the global object with a value of that
#: object, mapped to what a host running them prints: the object's own key names it, and the object
#: holds the global object the program reads it through.
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
    """
    Object folding removes the declaration of an object once it folded every reference the models
    listed before its copies. A copy that names the object through the global object makes a
    reference the list does not hold, and the declaration is removed under it.
    """

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


#: A classic script whose object holds the value of a global and, as a key, the name that global is
#: then written under through the global object, mapped to what a host running it prints.
A_GLOBAL_REWRITTEN_UNDER_A_KEY_OF_THE_OBJECT_HOLDING_ITS_VALUE = a_program("""
    var x = 1;
    function main() { var A = {k: "x", v: x}; globalThis[A.k] = 2; return A.v; }
    console.log(main());
    """)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAValueAnObjectHoldsIsReadWhereTheLiteralReadIt(TestBase):
    """
    Object folding checks that nothing writes a name an object's value reads before it decides the
    object, and the write `globalThis[A.k] = 2` names `x` only once the copy of `"x"` is made. The
    copy of `x` where `A.v` stood then reads the global after the write, which the literal read
    before it.
    """

    @wontfix(
        'a storage object holds strings and helper functions, not the value of a global it also '
        'names as a key that the program then writes under'
    )
    def test_the_value_is_the_one_the_literal_read(self):
        self.assertEqual(
            before_and_after_in_a_host(A_GLOBAL_REWRITTEN_UNDER_A_KEY_OF_THE_OBJECT_HOLDING_ITS_VALUE),
            (('1\n', None), ('1\n', None)),
        )


#: A program whose object holds an arrow function reading `new.target`, called from a nested
#: function, mapped to what Node prints for it.
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
    """
    An arrow function reads the `new.target` of the function it is written in. Object folding
    inlines the call `A.f()` into `h`, where `new.target` is the one of `h`, which a plain call
    leaves undefined.
    """

    @wontfix(
        'no obfuscator stores an arrow function reading new.target in an object, and a program '
        'calling one from another function is made up for the defect'
    )
    def test_the_arrow_reads_its_own_new_target(self):
        self.assertEqual(
            before_and_after(AN_ARROW_READING_NEW_TARGET_CALLED_FROM_A_NESTED_FUNCTION),
            (('true\n', None), ('true\n', None)),
        )


#: A program in which one inlined call of an object answers the name of the method that installs a
#: getter on every object, and a later call of the same object drops an argument that reads it,
#: mapped to what Node prints for it.
A_GETTER_ONE_CALL_INSTALLS_READ_IN_AN_ARGUMENT_ANOTHER_DROPS = a_program("""
    var O = {id: function (x) { return x; }, drop: function (a) { return 1; }};
    function h() { return ({}).q; }
    function later() { return O.drop(h()); }
    Object[O.id("defineProperty")](Object.prototype, "q", {get: function () { console.log("side"); return 1; }});
    console.log(later());
    """)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestACallOfAnObjectSeesWhatAnEarlierCallOfItShowed(TestBase):
    """
    Object folding inlines the calls of one object on the facts as they stand after its copies.
    Inlining `O.id("defineProperty")` makes the install of a getter on `Object.prototype` readable,
    but the call `O.drop(h())` is decided on facts without it: `h()` reads as free of effects and is
    dropped with the argument, and the getter's output is lost.
    """

    @wontfix(
        'storage objects hold no identity wrapper whose answer names an installer, and a getter '
        'on every object read by an argument a wrapper drops is made up for the defect'
    )
    def test_the_getter_still_runs(self):
        self.assertEqual(
            before_and_after(A_GETTER_ONE_CALL_INSTALLS_READ_IN_AN_ARGUMENT_ANOTHER_DROPS),
            (('side\n1\n', None), ('side\n1\n', None)),
        )


#: A program whose object is folded inside a `with` body whose object reads a name through a getter,
#: mapped to what Node prints for it.
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
    """
    The read of `Math` in the `with` body runs the getter of the `with` object. Object folding inlines
    `O.g(Math)` first and then asks whether reading the copy of `Math` it wrote has an effect. The
    held semantic model never saw that copy, does not place it in the `with` body, and answers that
    the read has none, so `O.f` drops it.
    """

    @wontfix(
        'obfuscated storage objects are not folded inside a with body whose object carries getters '
        'for the names their wrappers are handed'
    )
    def test_the_getter_still_runs(self):
        self.assertEqual(
            before_and_after(A_COPY_IN_A_WITH_BODY_READING_A_NAME_THROUGH_A_GETTER),
            (('got\nundefined\n', None), ('got\nundefined\n', None)),
        )


#: A classic script that replaces one of its top-level objects through the global object under a
#: key it holds in a variable, mapped to what a host running it prints.
AN_OBJECT_REPLACED_THROUGH_THE_GLOBAL_OBJECT_UNDER_A_RUNTIME_KEY = a_program("""
    var K = "C";
    var C = {x: 1};
    globalThis[K] = {x: 5};
    console.log(C.x);
    """)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnObjectReplacedThroughTheGlobalObjectUnderARuntimeKeyIsRead(TestBase):
    """
    A top-level variable of a classic script is a property of the global object, and a write to the
    global object under a key the models cannot read may replace it. Object folding folds `C.x` to
    the value of the literal all the same.
    """

    @wontfix(
        'a program replacing its own top-level object through the global object under a key it '
        'computes is made up for the defect'
    )
    def test_the_replaced_object_is_read(self):
        self.assertEqual(
            before_and_after_in_a_host(AN_OBJECT_REPLACED_THROUGH_THE_GLOBAL_OBJECT_UNDER_A_RUNTIME_KEY),
            (('5\n', None), ('5\n', None)),
        )


#: A program whose object literal names one key twice, the first time with a value that throws,
#: mapped to what Node prints for it.
AN_OBJECT_NAMING_A_KEY_TWICE_WITH_A_THROWING_VALUE_FIRST = a_program("""
    function f() { var O = {a: x, a: 2}; return O.a; }
    try { console.log(f()); } catch (e) { console.log(e.name); }
    """)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnEarlierValueOfAKeyNamedTwiceStillThrows(TestBase):
    """
    Object folding keeps the last value of a key a literal names twice and drops the earlier one with
    the declaration, without asking whether reading it throws. Building the literal reads `x`, which
    no declaration binds, and throws a `ReferenceError`.
    """

    @wontfix(
        'obfuscators emit every key of a storage object once, and a literal naming a key twice is '
        'made up for the defect'
    )
    def test_the_literal_still_throws(self):
        self.assertEqual(
            before_and_after(AN_OBJECT_NAMING_A_KEY_TWICE_WITH_A_THROWING_VALUE_FIRST),
            (('ReferenceError\n', None), ('ReferenceError\n', None)),
        )


#: A classic script whose object holds a function with a parameter named `eval` that it calls, mapped
#: to what a host running it prints.
A_PARAMETER_NAMED_EVAL_CALLED_IN_AN_INLINED_FUNCTION = a_program("""
    var O = {f: function (eval, s) { return eval(s); }};
    function main() { O.f(eval, "var x = 1"); return typeof x; }
    console.log(main());
    """)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAParameterNamedEvalRunsTheCodeInTheGlobalScope(TestBase):
    """
    Called through a parameter named `eval`, the function the parameter holds runs as an indirect
    `eval`, in the global scope. Inlining `O.f` writes `eval(s)` with the argument in place of the
    parameter where `main` calls it, a direct `eval` that declares `x` in `main`.
    """

    @wontfix(
        'no obfuscator names a parameter eval, and a program handing eval to a function whose '
        'parameter has that name is made up for the defect'
    )
    def test_the_code_runs_in_the_global_scope(self):
        self.assertEqual(
            before_and_after_in_a_host(A_PARAMETER_NAMED_EVAL_CALLED_IN_AN_INLINED_FUNCTION),
            (('undefined\n', None), ('undefined\n', None)),
        )


#: Programs that take the method installing a descriptor out of `Object` by destructuring and install
#: a key on every object with it, mapped to what Node prints: the key written as a name, and as a
#: computed string.
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
    """
    The models read a call of `Object.defineProperty`, or of a name a declaration gives it, as an
    install, but not a call of the name a destructuring of `Object` takes it out under. The install on
    `Object.prototype` is not seen, and object folding reads `B.q` as absent.

    The rule that closes it: a property a pattern takes out of a value is read as the member access
    of that value under the pattern's key, the way a declaration's initializer is.
    """

    @unittest.expectedFailure
    def test_the_install_is_seen(self):
        rows = AN_INSTALLER_TAKEN_BY_DESTRUCTURING
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


#: The programs of the same name in the file-kind tests, read as classic scripts.
A_NAMESPACE_AN_UNREADABLE_EVAL_CHANGES = as_classic_scripts(
    the_file_kind.A_NAMESPACE_AN_UNREADABLE_EVAL_CHANGES
)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_NAMESPACE_AN_UNREADABLE_EVAL_CHANGES)
class TestANamespaceAnUnreadableEvalReachesStaysWhole(TestBase):
    """
    Namespace flattening turns `X.k` into a variable `k` while a direct `eval` whose text the
    analysis cannot read still names `X`, and the `in` fold answers from the keys the text writes.
    The evaluated code deletes the key, so the input prints `false`, and the flattened output runs
    the same text against a name that no longer exists. In a module of either kind the namespace is
    within the reach of every direct `eval` of the file and stays whole; a classic script's is a
    global, which no `eval` is taken to reach. An `eval` beside a namespace is a shape packers do
    emit, but one whose text reaches back into the namespace is rare.
    """


#: A script whose recursive global function is called through the global object held under a name
#: the analysis does not take for it, before the value the function reads exists, mapped to the
#: behavior a host gives it.
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
    """
    A global function is called through `w.f`, where `w` is the global object a bare call's `this`
    hands out. The analysis does not take `w` for the global object, so it lists no call of `f`
    from outside `f` and orders the recursive function as though nothing called it before `c = 1`.
    The call reads `c` unset, and the deobfuscation writes `1` into `f`.
    """

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
    as `this`, so `this.undefined = 5` inside one rewrites the name for the whole script. The write
    is seen where the top level of the script spells it
    (`test.lib.scripts.js.analysis.test_differential.TestValueNameClobberedThroughTheGlobalObject`)
    but not inside a function, so a constant holding `undefined` is written as `void 0` and
    `typeof undefined` as a string. Nothing here runs a JScript engine, so the entry asserts that
    the name stays standing.
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


#: A module in an import cycle whose exported function reads a global the module creates only after
#: the other module of the cycle has called the function, mapped to that other module.
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
    """
    A module in an import cycle with the exporter can call an exported function before the
    exporter's body has finished. The analysis deciding whether a global exists at a read takes the
    calls the file spells for all the calls there are, so it vouches for `x` inside `f` and the
    read that throws when the importer calls `f` early is removed.
    """

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


#: A script whose declared entry point reads a constant the script defines before it first hands
#: the host control.
A_CONSTANT_DEFINED_BEFORE_THE_HOST_GETS_CONTROL = a_program("""
    const K = ['x'];
    function onload() { console.log(K[0]); }
    fire();
    """)


class TestAConstantDefinedBeforeTheHostGetsControlIsFoldedIntoAnEntryPoint(TestBase):
    """
    A host calls a declared entry point only while it holds control: during a call into code
    outside the file, such as `fire`, or once the script has finished. `K` is defined before
    either, so every call of `onload` reads it, but the ordering gives an entry point no reference
    points at all and keeps `K[0]`. Scripts declared with entry points are the analyst's choice,
    and a handler reading a table the script builds first is a common shape among them.
    """

    @unittest.expectedFailure
    def test_the_constant_is_folded(self):
        output = deobfuscate_source(
            A_CONSTANT_DEFINED_BEFORE_THE_HOST_GETS_CONTROL,
            entrypoints=('onload',),
        )
        self.assertEqual(
            ('function onload' in output, 'K[0]' in output),
            (True, False),
        )


#: A program whose function writes a variable that only it reads, and reads it again on its next
#: call, mapped to the behavior an engine gives it: a guard that lets the function run once, and a
#: counter.
A_WRITE_THE_NEXT_CALL_READS = {
    'a guard running the function once': Program(
        a_program("""
            var done;
            function once() { if (done) { return 'skip'; } done = true; return 'run'; }
            once();
            console.log(once());
            """),
        prints('skip'),
    ),
    'a counter': Program(
        a_program("""
            var n = 0;
            function next() { n = n + 1; return n; }
            next();
            console.log(next());
            """),
        prints('2'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_WRITE_THE_NEXT_CALL_READS)
class TestAWriteTheNextCallReadsIsKept(TestBase):
    """
    A write every reference of which stands inside the function performing it is taken as one no
    outside code observes, so a call whose value is discarded counts as free and is dropped. The
    function's own next call reads that write, so dropping the first call changes what the second
    one answers. Deciding it needs to know whether each call writes the variable before it reads
    it, which the effect model does not ask.
    """


#: A script whose function writes a variable a host reads by name once the script has run.
A_WRITE_A_HOST_READS = a_program("""
    var a;
    var f = function () { a = 2; return a; };
    console.log(f());
    """)


class TestAWriteAHostReadsIsKept(TestBase):
    """
    A variable declared as a host entry point is read from outside the file, as an exported one is
    read by an importer, so a function writing it cannot be replaced by the value it returns. The
    effect model counts the export as an observer of the write but is never told the entry points.
    """

    @unittest.expectedFailure
    def test_the_write_stays(self):
        output = deobfuscate_source(A_WRITE_A_HOST_READS, entrypoints=('a',))
        self.assertIn('a = 2', output)


#: A program declaring a `var` inside a `with` body whose object holds a property of the same name,
#: mapped to the behavior an engine gives it. The initializer writes the property, so the `var`
#: keeps `undefined`.
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
@one_expected_failure_per_program(A_VAR_INITIALIZED_INSIDE_A_WITH_BODY)
class TestAVarInitializedInsideAWithBodyMayWriteTheObject(TestBase):
    """
    The one value a binding holds is read from the initializer its declaration spells, and a
    declaration inside a `with` body is no exception, but the initializer assigns through the
    `with` object first: where the object has a property of that name, the property takes the
    value and the `var` keeps `undefined`. Control-flow flattening writes `var` declarations inside
    `with` bodies, so the shape is one an obfuscator emits whenever its scope object carries the
    declared name.
    """


#: A classic script writing one of its own top-level variables through the global object it
#: obtains by running `return this` as a function body, mapped to the behavior a host gives it.
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
@one_expected_failure_per_program(A_GLOBAL_WRITTEN_THROUGH_A_FOUND_GLOBAL_OBJECT)
class TestAGlobalWrittenThroughAFoundGlobalObjectChangesTheVariable(TestBase):
    """
    `Function('return this')()` is the global object, and a store on it under a variable's name is
    a write of that variable. The model knows the global object by the names it is spelled with
    and by the locals holding one of them, not by the value this call returns, so the write is
    not seen and the value the declaration spelled is read in its place.
    """


#: Programs whose Annex B `var` inside a `catch` clause shares the name of the clause's parameter,
#: mapped to what Node prints: the initializer writes the parameter, and the `var` keeps
#: `undefined`.
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
    """
    A `var` declared inside a `catch` clause under the name of the clause's parameter is hoisted
    out of the clause, but its initializer assigns the parameter, so the `var` itself is never
    written. The model reads the initializer as the value of the `var`.
    """

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


#: A program whose recursive function stores a closure in an outer variable on every run and
#: calls it after a nested run has replaced it, mapped to what Node prints: the closure of the
#: nested run, which returned before its own `var` was written.
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
    """
    The ordering attributes every call of a function to one run of the function that created it.
    A recursive function storing a new closure on every run breaks that: the closure called after
    the nested run returned belongs to the nested run, whose `var` was never written.
    """

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


#: Programs that make a decided self-check trip through a route made up for it, each mapped to
#: what Node prints: `Function.prototype` reached through `__proto__`, the `caller` key spelled
#: at runtime, an empty function written over two lines that namespace flattening rebuilds on one,
#: the match statics of `RegExp` read after a guarded call through a key built at runtime or
#: through `RegExp.input`, which holds the text the hash read, and the checked function reached
#: without its name: through the legacy `arguments` of a function it was handed to, through
#: `arguments.callee` of an object's own `apply` or of a callback run as `arguments[0]()`, through
#: the stack a replaced `Error.prepareStackTrace` hands out, and through the catch parameter a
#: `var` of the same name writes. The last row reads a `let` of the hash helper before it is
#: declared, which throws where the helper's template computes the hash.
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
    """
    `refinery.lib.scripts.js.deobfuscation.selfchecks` decides each of these checks as the input
    text answers it, and each program makes the check answer otherwise through a route no
    obfuscator writes.
    """

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


#: A function that unpacks its argument into a constant and assigns the constant inside a `try`,
#: mapped to what Node prints for it: the assignment throws a `TypeError`, which the `catch`
#: returns.
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
    """
    An assignment to a `const` binding throws a `TypeError` where it runs, so it is no store a pass
    may drop for being unread, and the `catch` around it reports the error. The deobfuscation drops
    the assignment, and the function returns from the `try`. No program assigns a constant on
    purpose, which is why this is not held against a release.
    """

    @unittest.expectedFailure
    def test_the_assignment_still_throws(self):
        rows = AN_ASSIGNMENT_TO_A_CONSTANT_INSIDE_A_TRY
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


#: Functions that assign a constant and return what they then read, mapped to what Node makes of
#: each: the assignment throws a `TypeError`, which the first returns from its `catch` and which
#: ends the second.
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
    """
    The assignment of `TestAnAssignmentToAConstantStillThrows`, reached through a call that the
    deobfuscation evaluates rather than through a store that it drops: the evaluation completes the
    assignment the engine refuses, and the call folds to what the function returns after it. No
    program assigns a constant on purpose, which is why this is not held against a release.
    """

    @unittest.expectedFailure
    def test_the_evaluated_assignment_still_throws(self):
        rows = A_CALL_THAT_ASSIGNS_A_CONSTANT
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            {source: (behavior, behavior) for source, behavior in rows.items()},
        )


#: A function whose parameter shares its name with a property of a namespace object it declares,
#: and which reads its argument back through `arguments`, mapped to what Node prints for it.
A_NAMESPACE_PROPERTY_NAMED_LIKE_A_PARAMETER = {
    a_program("""
        function f(a) { var NS = {}; NS.a = 1; return arguments[0]; }
        console.log(f(5));
        """): '5\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFlattenedNamespaceLeavesTheArgumentsAlone(TestBase):
    """
    Flattening a namespace object turns each of its properties into a variable of the function. A
    variable named like a parameter of a function with simple parameters is that parameter, and
    `arguments[0]` reads what the parameter holds, so the flattened store writes the argument the
    program reads back.
    """

    @unittest.expectedFailure
    def test_the_argument_is_read_back(self):
        rows = A_NAMESPACE_PROPERTY_NAMED_LIKE_A_PARAMETER
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


#: A classic script that assigns `eval` to itself and calls it on code reading a global, mapped to
#: what Node makes of it: the call still runs the code, which reads the global.
A_SCRIPT_THAT_ASSIGNS_EVAL = {
    a_program("""
        var x = 1;
        function keep() { eval = eval; }
        eval("console.log(x)");
        """): ('1\n', None),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnEvalTheScriptAssignsIsStillEval(TestBase):
    """
    An assignment to `eval` makes the name a binding of the script, and the model then reads every
    call of it as a call of that binding rather than of the intrinsic, so the code it runs is no
    longer counted as reading the globals around it.
    """

    @wontfix('no program assigns eval to a name of its own, and an obfuscator that hides eval aliases it')
    def test_the_global_the_code_reads_stays(self):
        rows = A_SCRIPT_THAT_ASSIGNS_EVAL
        self.assertEqual(
            {source: before_and_after_in_a_host(source) for source in rows},
            {source: (behavior, behavior) for source, behavior in rows.items()},
        )


#: A function nothing calls, beside a nested function that declares a name of its own spelled like
#: it, mapped to what the deobfuscation writes once the function is removed.
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
    """
    `refinery.lib.scripts.js.deobfuscation.unused.JsUnusedCodeRemoval` decides whether a function
    declaration is reachable by the names the statements around it spell, so a function nothing
    calls is kept wherever a nested function declares a name of its own spelled the same. The
    renaming setting of an obfuscator gives functions of different scopes one name, so the
    deobfuscation of its output keeps functions nothing calls. The fix is to decide reachability
    through the references the semantic model records.
    """

    @unittest.expectedFailure
    def test_the_function_nothing_calls_is_removed(self):
        rows = A_FUNCTION_ONLY_A_SHADOWING_NAME_SPELLS
        self.assertEqual({source: folded(source) for source in rows}, rows)


#: Programs whose concealed strings the base91 pass decodes although the program changes what a
#: decoded string is, each through a shape the obfuscator never writes, mapped to what Node prints:
#: the function turning bytes into a string assigned after an early call, turning them into
#: something other than their UTF-8 text, or supplied by a `with` object around the decoder; a
#: second accessor filling a slot of the shared cache from a table of its own; an index the program
#: puts on the object prototype, which the cache inherits; and a `slice` it puts on the string
#: prototype, which an accessor slicing one long string calls.
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
    """
    `refinery.lib.scripts.js.deobfuscation.b91strings` reads a decoder and an accessor by their
    templates and trusts what the obfuscator writes around them: its own function turning UTF-8
    bytes into a string, declared before anything runs; one table index per string, so no two
    accessors fill one slot of the cache; and prototypes nobody writes.
    """

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


#: A classic script that evaluates code at runtime naming the accessor of its concealed strings,
#: mapped to what a host prints for it.
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
    """
    `refinery.lib.scripts.js.deobfuscation.b91strings` removes its machinery once nothing the model
    records names it, a `with` body included. Code a script evaluates at runtime runs in the global
    scope and may name a function the script declares there, which no reference records.
    """

    @wontfix('the obfuscator names its machinery with made-up names, which no code evaluated at runtime spells')
    def test_the_host_prints_what_the_script_prints(self):
        rows = AN_ACCESSOR_NAMED_BY_CODE_EVALUATED_AT_RUNTIME
        self.assertEqual(
            {source: before_and_after_in_a_host(source) for source in rows},
            each_program_still_prints(rows),
        )


#: A program putting an index on the array prototype that a function whose parameters are masked
#: in a rest array reads through a slot it never wrote, mapped to what Node prints.
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
    """
    `refinery.lib.scripts.js.deobfuscation.restunpack` refuses a key the language's array prototype
    supplies, but a slot the program put on that prototype itself becomes a fresh name holding
    `undefined`.
    """

    @wontfix('no program puts an index on the array prototype that a masked function reads unwritten')
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        rows = AN_INDEX_A_MASKED_ARRAY_INHERITS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAScriptKeptForItsValueEndsOnTheValueOfItsLastStore(TestBase):
    """
    Under `preserve_script_return`,
    `refinery.lib.scripts.js.deobfuscation.unused.JsUnusedCodeRemoval` removes a store to a
    declared name nothing reads although the script ends on it: the value of the script is the value
    of its last statement with one, and a store is such a statement. The sweep of stores to
    properties of the global object already spares a store that
    `refinery.lib.scripts.js.deobfuscation.helpers.reaches_script_completion` places at the end of
    the script; the removal of a store to a declared name has to ask the same question. Node
    evaluates the script below to `5`, and the deobfuscation to `undefined`.
    """

    @unittest.expectedFailure
    def test_the_script_ends_on_the_value_of_its_last_store(self):
        source = 'var acc;\nacc = 5;\n'
        deobfuscated = deobfuscate_source(source, preserve_script_return=True)
        for evaluation in JsEvaluation:
            with self.subTest(evaluation=evaluation.value):
                self.assertEqual(
                    completion_values([deobfuscated], evaluation),
                    completion_values([source], evaluation),
                )


#: Programs reading an alias of a built-in in the initializer of an instance field and replacing
#: the alias between the class statement and the construction, mapped to what Node prints.
AN_ALIAS_A_FIELD_READS_REPLACED_BEFORE_CONSTRUCTION = {
    inspect.cleandoc('''
        function f(s) {
          var F;
          F = Function;
          class A { x = F("return 7")(); }
          eval(s);
          return new A().x;
        }
        console.log(f("F = function () { return function () { return 8; }; };"));
    '''):
        '8\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnAliasAFieldReadsIsTheOneInPlaceWhenAnInstanceIsConstructed(TestBase):
    """
    The root of
    `test.lib.scripts.js.test_release_blockers.TestAFieldReadsAVariableWhenAnInstanceIsConstructed`
    with an alias of `Function` for the variable: constant inlining takes the read in the field to
    happen at the class statement and writes `Function` into it, though an `eval` replaces the
    alias before the construction.
    """

    @wontfix(
        'no obfuscated file replaces an alias of Function through an eval between a class '
        'statement and the construction of an instance; this is made up for the defect'
    )
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        rows = AN_ALIAS_A_FIELD_READS_REPLACED_BEFORE_CONSTRUCTION
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


#: Programs writing a key into the prototype every object literal inherits from, through another
#: object, and asking an empty object literal for the key with `in`, mapped to the behavior an
#: engine gives them.
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
@one_expected_failure_per_program(A_KEY_WRITTEN_INTO_THE_OBJECT_PROTOTYPE_THROUGH_ANOTHER_OBJECT)
class TestAKeyWrittenIntoTheObjectPrototypeThroughAnotherObjectIsInherited(TestBase):
    """
    Every object literal inherits from `Object.prototype`, so a key written there is found by `in`
    on any of them. The question whether the program writes that prototype
    (`refinery.lib.scripts.js.analysis.effects.EffectModel.read_chain_intact`) recognizes a write
    spelled through `Object.prototype` or a constructor's `prototype`, but not one through the
    `__proto__` of another object or through `Object.getPrototypeOf`, so the fold of `in` over an
    empty object literal answers `false`. Programs write a prototype this way rarely, and then
    mostly to pollute it on purpose.
    """


#: Programs copying a name nothing binds into a local and asking `typeof` of the local, mapped to
#: the behavior an engine gives them.
A_TYPEOF_OF_A_LOCAL_HOLDING_A_NAME_NOTHING_BINDS = {
    'a local at the top of the file': Program(
        a_program("""
            var r = someGlobal;
            console.log(typeof r);
            """),
        ('', 'ReferenceError'),
    ),
    'a local of a packed program holding require, run as an ES module': Program(
        a_program("""
            Function("p", "var r = p.r; console.log(typeof r)")({ get r() { return require; } });
            """),
        ('', 'ReferenceError'),
        Reading.ES_MODULE,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_TYPEOF_OF_A_LOCAL_HOLDING_A_NAME_NOTHING_BINDS)
class TestATypeofOfALocalHoldingANameNothingBindsStillThrows(TestBase):
    """
    Reading a name nothing binds throws a `ReferenceError`, and `typeof` of such a name answers
    `'undefined'` instead. The deobfuscation writes the name where the local holding it is read, so
    `typeof r` becomes `typeof someGlobal`, and the program that threw on the copy prints
    `undefined`. A packed program reaches the shape when it copies a name the accessor object reads
    for it into a local, which the obfuscator does not write itself; the program it wraps may.
    """


#: A program starting a timer with a string, which Node refuses, mapped to the behavior Node gives
#: it.
A_STRING_TIMER_THE_HOST_REFUSES = {
    'a string timer under Node': Program(
        a_program("""
            try { setTimeout("console.log(1)", 0); } catch (e) { console.log(e.name); }
            """),
        prints('TypeError'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_STRING_TIMER_THE_HOST_REFUSES)
class TestAStringTimerTheHostRefusesStillThrows(TestBase):
    """
    A browser compiles a string handed to `setTimeout` and runs it when the timer fires; Node
    accepts only a function and throws a `TypeError`. The reflection pass lowers a string timer to a
    function wrapping its code whatever the host, so the program that caught a `TypeError` under
    Node prints `1` instead. The lowering holds only where the host is known to compile the string,
    which neither the default host nor `-e node` is.
    """


#: Packed programs calling a global function through the accessor object, where the function reads
#: `this`, mapped to the behavior an engine gives them.
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

#: The packer's output for the program of the row above, read as text only.
PACKED_THIS = (
    r'Function("cP2i872","globalThis[\"helper\"]=function(){return this===globalThis};return c'
    r'onsole[\"log\"](cP2i872[\"JC7DQ0X\"]());")({get"JC7DQ0X"(){return helper}});'
)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_FUNCTION_CALLED_THROUGH_THE_PACKED_ACCESSOR_OBJECT)
class TestAFunctionCalledThroughThePackedAccessorObjectKeepsItsReceiver(TestBase):
    """
    A call through a key of the accessor object runs the function the getter returns with the
    accessor object as `this`; the bare call that unpacking writes runs it with `undefined`, which
    sloppy code reads as the global object. The packer writes every call of a global function this
    way, and most such functions never read `this`, so refusing every such call would keep most
    packed programs packed; telling them apart needs to know what the callee reads.
    """

    @unittest.expectedFailure
    def test_the_packers_own_output_does_not_call_the_function_bare(self):
        output = deobfuscate_source(PACKED_THIS, execution=ExecutionModel.commonjs)
        self.assertNotIn('helper()', output)


#: A program awaiting at the top level of a file no package marks as a module, mapped to the
#: behavior Node gives it.
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
@one_expected_failure_per_program(A_FILE_AWAITING_AT_ITS_TOP_LEVEL)
class TestAFileAwaitingAtItsTopLevelIsAnEsModule(TestBase):
    """
    Node runs a `.js` file as an ES module when the file spells what only a module may, and a
    top-level `await` is such a spelling. The parser reads no top-level `await`
    (`TestAModulesTopLevelAwaitIsAProgram`), so under `-c` the file is taken for CommonJS, which is
    sloppy code, and a payload only sloppy code runs as written is unpacked into strict code.
    """


#: A program that is an ES module only because it declares a name the CommonJS wrapper binds,
#: mapped to the behavior Node gives it.
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
    """
    A `const` declaring `exports` at the top of a file redeclares a parameter of the CommonJS
    wrapper, so Node cannot compile the file as CommonJS and runs it as an ES module instead. The
    deobfuscation removes the declaration nothing reads, and Node runs what is left as CommonJS,
    where `this` is an object and `require` is bound.
    """

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


#: Programs whose function declares a variable of its own, lifted to the top of a classic script,
#: mapped to the behavior a host gives them.
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
@one_expected_failure_per_program(A_FUNCTIONS_OWN_VARIABLE_LIFTED_INTO_A_SCRIPT)
class TestAFunctionsOwnVariableStaysOffTheGlobalObject(TestBase):
    """
    A variable a function declares is its own. Spliced into the top of a classic script, the
    declaration makes it a property of the global object, which other scripts see and which may be
    one the host already has: in a browser, a `var status` lifted this way writes the window's own.
    The reflection pass lifts the declarations of a `Function` body this way, and the single-use
    function inliner those of the function it inlines. Refusing every such lift would keep most
    wrapped scripts wrapped.
    """


#: A program whose direct `eval` declares a function the file declares as well, mapped to the
#: behavior Node gives it.
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
    """
    A sloppy direct `eval` declaring a function the scope already declares replaces it when the
    `eval` runs. The call wrapper inliner reads the call from the declaration of the file and folds
    it to the value that function returns.
    """

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


#: Packed programs whose access through the accessor object the unpacked program makes otherwise,
#: each made as the program the packer was given made it, mapped to the behavior Node gives them as
#: a CommonJS file.
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
    """
    The accessors of the accessor object stand at the top of the file: the setter writes a global
    as sloppy code, its value is an argument, which no function takes its name from, and the name
    each accessor spells resolves outside every `with` body of the packed program. The unpacked
    access is the one the program the packer was given made: inside a class body it is strict code
    and throws where the global may not be written, an anonymous function written to the name is
    named after it, and inside a `with` body whose object holds the name it reaches the object.
    """

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


#: A program deleting a variable a direct `eval` declared, mapped to the behavior Node gives it as
#: a CommonJS file.
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
    """
    A variable a sloppy direct `eval` declares can be deleted, and one the text declares cannot, so
    once the `eval` is inlined `delete q` answers `false` and leaves the variable in place.
    """

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


#: A program calling `execScript` under Node, mapped to the behavior Node gives it.
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
    """
    Only Internet Explorer defines `execScript`; elsewhere a call of it throws a `ReferenceError`.
    The reflection pass inlines the string it is given whatever the host, so under Node the program
    that caught the error runs the string instead.
    """

    @wontfix('no program run by Node calls execScript, which only Internet Explorer defines')
    def test_the_deobfuscation_behaves_as_the_program_does(self):
        rows = A_STRING_RUN_BY_EXECSCRIPT_UNDER_NODE
        self.assertEqual(
            {label: row.read() for label, row in rows.items()},
            {label: row.required() for label, row in rows.items()},
        )


#: A program whose fold rests on code being sloppy where its text does not make it strict, mapped
#: to the behavior Node gives it as an ES module.
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
@one_expected_failure_per_program(A_FOLD_RESTING_ON_SLOPPY_CODE_IN_AN_ES_MODULE)
class TestAFoldRestingOnSloppyCodeHoldsInAnEsModule(TestBase):
    """
    Under `-m` the file may be an ES module, which is strict code throughout, so a fold is sound
    only where it holds for strict code as well. The global finder takes `this` of a function
    called bare for the global object, which is `undefined` in strict code, where the value it
    returns is `r || this` and `r` may be `undefined` on the path through the `catch`: it judges
    the value as a whole, not each path into it.
    """


#: A program that holds `require` under another name and loads a file through it before a `typeof`
#: of a name the file creates, mapped to the behavior Node gives it as a CommonJS file.
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
@one_expected_failure_per_program(A_FILE_REQUIRED_THROUGH_ANOTHER_NAME)
class TestAFileRequiredThroughAnotherNameIsALoad(TestBase):
    """
    A file the program has `require` load may set up a global name, so a `typeof` of such a name
    folds only where no load may precede it
    (`refinery.lib.scripts.js.analysis.model.SemanticModel.code_load_sites`). Only a call of the
    name `require` itself counts as a load: a real program holds `require` under another name and
    calls it with the names of built-in modules, and a site at every read of the value would order
    nothing after it. A file loaded through that other name is not seen.
    """


#: Programs whose accessor a function called where it is written builds over values it closes over,
#: mapped to the behavior Node gives each as a CommonJS file.
AN_ACCESSOR_BUILT_OVER_VALUES_IT_CLOSES_OVER = {
    'the accessor writes into the array it closes over': Program(
        a_program("""
            var X = function () { var a = [0]; return function () { a[0]++; return a[0]; }; }();
            console.log(X(), X(), X());
            """),
        prints('1 2 3'),
        Reading.COMMONJS,
    ),
    'the name is read before the accessor is built': Program(
        a_program("""
            console.log(typeof X);
            var X = function () { var a = [1, 2]; return function (i) { return a[i]; }; }();
            console.log(X(0));
            """),
        prints('undefined', '1'),
        Reading.COMMONJS,
    ),
    'the accessor returns the array it closes over': Program(
        a_program("""
            var X = function () { var a = [1, 2]; return function () { return a; }; }();
            console.log(X() === X());
            """),
        prints('true'),
        Reading.COMMONJS,
    ),
    'the accessor stores into an object it closes over': Program(
        a_program("""
            var X = function () { var c = {}; return function (k) { c[k] = (c[k] || 0) + 1; return c[k]; }; }();
            console.log(X("a"), X("a"));
            """),
        prints('1 2'),
        Reading.COMMONJS,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(AN_ACCESSOR_BUILT_OVER_VALUES_IT_CLOSES_OVER)
class TestAnAccessorBuiltOverValuesItClosesOverIsPromotedOnlyWhereThatHolds(TestBase):
    """
    `refinery.lib.scripts.js.deobfuscation.iifeaccessor` rewrites `var X = function () { var a =
    [...]; return function (...) {...}; }()` into a function declaration that builds the closed-over
    values inside itself, without asking the model whether that keeps what the program computes. A
    write into the closed-over array then runs on a fresh array at every call, a returned array is a
    new one each call, and the declaration is hoisted above reads that saw `undefined`. The rewrite
    holds only for values no call writes, hands out, or is read before the build.
    """


#: A program that has `require` load a file replacing a built-in method before a call of that method
#: on a literal, mapped to the behavior Node gives it as a CommonJS file.
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
@one_expected_failure_per_program(A_LOADED_FILE_REPLACING_A_BUILTIN)
class TestALoadedFileReplacingABuiltinHoldsTheFoldBack(TestBase):
    """
    A file the program has `require` load is a site of the tampering oracle
    (`refinery.lib.scripts.js.analysis.model.SemanticModel.code_load_sites`), but the oracle is
    asked only where a program-wide trust question refuses, and those questions know nothing of
    loads: a load is no reflection surface, since dead code holds `require` calls in functions
    nothing calls, and a surface there would withdraw every program-wide trust. So a method a loaded
    file replaces is folded as the language's own wherever the program writes nothing that disturbs
    it. Closing it means the program-wide questions asking the loads ordered against their point,
    which every consumer of them would have to supply.
    """


#: Programs reading the `length` of a function whose rest parameter a pass gives the parameters it
#: reads, mapped to the behavior Node gives each as a CommonJS file: the rest array the masking
#: writes, and the arguments the control-flow recovery finds stored into its scope object.
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
@one_expected_failure_per_program(A_LENGTH_AN_UNPACKED_REST_PARAMETER_CHANGES)
class TestAnUnpackedRestParameterKeepsTheLengthOfTheFunction(TestBase):
    """
    `refinery.lib.scripts.js.deobfuscation.restunpack` and the control-flow recovery of
    `refinery.lib.scripts.js.deobfuscation.cff.statemachine` give a function `(...s)` the parameters
    it reads out of `s` as plain names, which turns its `length` of 0 into their count. A correct
    pass writes `(...[a, b])`, which keeps the length 0, wherever the `length` of the function is
    read (`refinery.lib.scripts.js.deobfuscation.parameters.function_length_unobserved`), and the
    plain names elsewhere.
    """
