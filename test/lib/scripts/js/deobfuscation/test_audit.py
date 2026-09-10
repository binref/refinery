"""
Which pass left a body running in the other mode, and which pass moved no mode at all.

`refinery.lib.scripts.js.deobfuscation.audit.StrictModeAudit` is the outside view of a run: it reads
the mode of every body around every transformer invocation and names the pass after which a body
that was already in the tree runs in the other mode. Which bodies of a program run in strict mode is
nothing a transform decides, so a report is a defect and an empty report is what a run over a
program the tool handles has to produce.

Two things are law here and they are not the same thing. A pass that changes how many strict bodies
a program has moved no mode: a strict function nothing calls that is swept away, one that is folded
into its call site, and one a promotion builds are each a body that went or came, and a body that is
not there ran in no mode at all. A pass that leaves a body where it was and changes the mode it runs
in did move one, whether it wrote a statement above the directive, took the directive away, or
carried the body out of the region that governed it.

Node decides every mode this file records. The probe is an assignment to `NaN`, a property of the
global object no program may write: the write is discarded where the code around it is sloppy and
throws a `TypeError` where that code is strict, so a body making one says which mode the engine
compiled it in. It is written as a statement rather than as the `this` of a plain call, which is the
probe `test.lib.scripts.js.test_directive_prologue` asks with, because that call needs a function to
stand in and a law quantified over *every* body of a program may not add a body to each body it
measures. Where a program is handed to the deobfuscator rather than only to the engine, the probe
that adds a body is the one used, since there the count of bodies is what is at stake and no law is
quantified over them.

SECURITY: every snippet here is hand-authored and benign, and running it is what makes the engine
the oracle. Nothing from `samples` may ever be fed to this.
"""
from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import (
    behavior,
    deobfuscate_source,
    node_executable,
)
from test.lib.scripts.js.test_directive_prologue import A_PROGRAM_REPORTING_ITS_MODE

from refinery.lib.scripts import Node, Transformer, set_body
from refinery.lib.scripts.js.deobfuscation import deobfuscate
from refinery.lib.scripts.js.deobfuscation.audit import StrictModeAudit, mode_of_every_body
from refinery.lib.scripts.js.model import (
    JsBlockStatement,
    JsFunctionDeclaration,
    JsIdentifier,
    JsScript,
    JsStringLiteral,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsVarKind,
)
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.strict import (
    declares_use_strict,
    is_prologue_host,
    is_use_strict_directive,
)
from refinery.lib.scripts.js.synth import JsSynthesizer
from refinery.lib.scripts.pipeline import TransformerGroup

_THE_GROUP = 'probe'


def _reports(label: str) -> str:
    """
    A statement printing whether the code it stands in runs in strict mode, under *label*.
    """
    return (
        F"try {{ NaN = 1; console.log('{label}=false'); }}"
        F" catch (e) {{ console.log('{label}=true'); }}"
    )


#: A program every body of which prints the mode it runs in, mapped to the mode of each of them.
#: Between them they cover a body strict for the directive it holds, one strict for a directive
#: standing above it, one strict for the class it belongs to, and one sloppy beside a strict one.
A_PROGRAM_WHOSE_EVERY_BODY_REPORTS_ITS_MODE = {
    F"{_reports('top')}\nfunction f() {{ {_reports('f')} }}\nf();\n": {
        'top' : False,
        'f'   : False,
    },
    F"'use strict';\n{_reports('top')}\nfunction f() {{ {_reports('f')} }}\nf();\n": {
        'top' : True,
        'f'   : True,
    },
    F"{_reports('top')}\nfunction f() {{ 'use strict'; {_reports('f')} }}\n"
    F"function g() {{ {_reports('g')} }}\nf();\ng();\n": {
        'top' : False,
        'f'   : True,
        'g'   : False,
    },
    F"{_reports('top')}\nfunction f() {{ 'use strict'; function g() {{ {_reports('g')} }}"
    F" g(); {_reports('f')} }}\nf();\n": {
        'top' : False,
        'f'   : True,
        'g'   : True,
    },
    F"{_reports('top')}\nclass C {{ static {{ {_reports('block')} }}"
    F" m() {{ {_reports('m')} }} }}\nnew C().m();\n": {
        'top'   : False,
        'block' : True,
        'm'     : True,
    },
    F"{_reports('top')}\nvar o = {{ m() {{ {_reports('m')} }},"
    F" get p() {{ {_reports('p')} }} }};\no.m();\no.p;\n": {
        'top' : False,
        'm'   : False,
        'p'   : False,
    },
    F"{_reports('top')}\nfunction f() {{ 'use strict';"
    F" var a = () => {{ {_reports('a')} }}; a(); {_reports('f')} }}\nf();\n": {
        'top' : False,
        'f'   : True,
        'a'   : True,
    },
    F"{_reports('top')}\nvar f = function () {{ {_reports('f')} }};\nf();\n": {
        'top' : False,
        'f'   : False,
    },
}

#: The same, for a program the engine reads as a module. Module code is strict throughout whatever
#: any body in it declares, and nothing but the `export` decides it.
A_MODULE_WHOSE_EVERY_BODY_REPORTS_ITS_MODE = {
    F"export {{}};\n{_reports('top')}\nfunction f() {{ {_reports('f')} }}\nf();\n": {
        'top' : True,
        'f'   : True,
    },
}

#: A script holding one sloppy body and one strict body, which the edits below move a mode in.
A_STRICT_FUNCTION_IN_A_SLOPPY_SCRIPT = (
    F"{_reports('top')}\nfunction f() {{ 'use strict'; {_reports('f')} }}\nf();\n"
)


class ADeclarationWrittenAboveTheDirective(Transformer):
    """
    Writes a declaration at the head of a body that opens with the directive, which is what a pass
    does that hoists a local into a body it is rewriting. The directive is left where it was and
    stops being one, a Directive Prologue being the run of string literals a body *opens* with.
    """

    def visit_JsFunctionDeclaration(self, node: JsFunctionDeclaration):
        body = node.body
        if not isinstance(body, JsBlockStatement) or not body.body:
            return
        if not is_use_strict_directive(body.body[0]):
            return
        declaration = JsVariableDeclaration(
            declarations=[JsVariableDeclarator(id=JsIdentifier(name='t'))],
            kind=JsVarKind.VAR,
        )
        set_body(body, [declaration, *body.body])
        self.mark_changed()


class TheDirectiveSweptOutOfTheBody(Transformer):
    """
    Drops the directive from a body that holds one, which is what a sweep does that reads a
    statement evaluating a literal as a statement computing nothing.
    """

    def visit_JsFunctionDeclaration(self, node: JsFunctionDeclaration):
        body = node.body
        if not isinstance(body, JsBlockStatement):
            return
        kept = [
            statement for statement in body.body
            if not is_use_strict_directive(statement)
        ]
        if len(kept) == len(body.body):
            return
        set_body(body, kept)
        self.mark_changed()


class ABodyLiftedOutOfTheFunctionAroundIt(Transformer):
    """
    Moves a function declaration out of the body holding it and onto the end of the script, which is
    what a promotion does. Nothing is written or removed and the declaration is hoisted either way,
    so the call reaches it from where it stood before.
    """

    def visit_JsScript(self, node: JsScript):
        for outer in node.body:
            if not isinstance(outer, JsFunctionDeclaration):
                continue
            body = outer.body
            if not isinstance(body, JsBlockStatement):
                continue
            lifted = [s for s in body.body if isinstance(s, JsFunctionDeclaration)]
            if not lifted:
                continue
            set_body(body, [s for s in body.body if not isinstance(s, JsFunctionDeclaration)])
            set_body(node, [*node.body, *lifted])
            self.mark_changed()
            return


class ABodyMovedIntoTheFunctionBesideIt(Transformer):
    """
    Moves the second function declaration of the script into the body of the first, which is the
    same move the other way around.
    """

    def visit_JsScript(self, node: JsScript):
        functions = [s for s in node.body if isinstance(s, JsFunctionDeclaration)]
        if len(functions) < 2:
            return
        host, moved = functions[0], functions[1]
        body = host.body
        if not isinstance(body, JsBlockStatement):
            return
        set_body(node, [s for s in node.body if s is not moved])
        set_body(body, [*body.body, moved])
        self.mark_changed()


class EveryStrictFunctionDropped(Transformer):
    """
    Removes every function declaration whose body opens with the directive, taking those bodies away
    rather than moving the mode of any body that stays.
    """

    def visit_JsScript(self, node: JsScript):
        kept = [
            statement for statement in node.body
            if not isinstance(statement, JsFunctionDeclaration)
            or not declares_use_strict(statement.body)
        ]
        if len(kept) == len(node.body):
            return
        set_body(node, kept)
        self.mark_changed()


#: An edit made to a program, mapped to that program and to what the edit leaves running in the
#: other mode: the label each such body prints its mode under, mapped to the mode it now runs in.
#: The last edit takes bodies away rather than moving any, and leaves nothing in the other mode.
AN_EDIT_AND_THE_BODIES_IT_LEAVES_IN_THE_OTHER_MODE: dict[
    type[Transformer], tuple[str, dict[str, bool]]
] = {
    ADeclarationWrittenAboveTheDirective: (
        A_STRICT_FUNCTION_IN_A_SLOPPY_SCRIPT,
        {'f': False},
    ),
    TheDirectiveSweptOutOfTheBody: (
        A_STRICT_FUNCTION_IN_A_SLOPPY_SCRIPT,
        {'f': False},
    ),
    ABodyLiftedOutOfTheFunctionAroundIt: (
        F"{_reports('top')}\nfunction f() {{ 'use strict'; function g() {{ {_reports('g')} }}"
        F" g(); {_reports('f')} }}\nf();\n",
        {'g': False},
    ),
    ABodyMovedIntoTheFunctionBesideIt: (
        F"{_reports('top')}\nfunction f() {{ 'use strict'; g(); {_reports('f')} }}\n"
        F"function g() {{ {_reports('g')} }}\nf();\n",
        {'g': True},
    ),
    EveryStrictFunctionDropped: (
        F"{_reports('top')}\nfunction d() {{ 'use strict'; {_reports('d')} }}\n"
        F"function f() {{ {_reports('f')} }}\nf();\n",
        {},
    ),
}

#: An expression that is `true` where it stands in strict code and `false` where it stands in sloppy
#: code, as `test.lib.scripts.js.test_directive_prologue` writes it.
_THE_MODE_IT_STANDS_IN = '(function () { return this; })() === undefined'

#: A number the tool cannot compute, so that a body reading it is one no fold answers for.
_A_NUMBER_ONLY_THE_HOST_KNOWS = 'process.argv.length'


def _returns_the_mode_it_stands_in(value: str) -> str:
    return F"return {value} + ({_THE_MODE_IT_STANDS_IN} ? 'S' : 'L');"


#: A program a pass adds or removes a strict body in, mapped to what Node prints for it. A body is
#: swept away, folded into its call site, built by a promotion and folded away again, built by a
#: promotion and kept, moved out of the object holding it, and left where it was; every one of them
#: that survives says which mode it runs in, so a mode that moved would be a text that prints
#: differently.
A_PROGRAM_A_PASS_ADDS_OR_REMOVES_A_STRICT_BODY_IN = {
    "function d() { 'use strict'; console.log('d'); }\n"
    F'console.log({_THE_MODE_IT_STANDS_IN});\n':
        'false\n',
    "function w(a) { 'use strict'; return a + 1; }\nconsole.log(w(1));\n":
        '2\n',
    'var acc = (function () {\n'
    "  var t = ['a', 'b'];\n"
    "  return function (i) { 'use strict'; return t[i] + i; };\n"
    '})();\nconsole.log(acc(1));\n':
        'b1\n',
    'var acc = (function () {\n'
    "  var t = ['a', 'b'];\n"
    F"  return function (i) {{ 'use strict'; {_returns_the_mode_it_stands_in('t[i]')} }};\n"
    F'}})();\nconsole.log(acc({_A_NUMBER_ONLY_THE_HOST_KNOWS} - 2));\n':
        'aS\n',
    'var NS = {};\n'
    F"NS.f = function (a) {{ 'use strict'; {_returns_the_mode_it_stands_in('a')} }};\n"
    F'console.log(NS.f({_A_NUMBER_ONLY_THE_HOST_KNOWS}));\n':
        '2S\n',
    F"function f(a) {{ 'use strict'; {_returns_the_mode_it_stands_in('a')} }}\n"
    F'console.log(f({_A_NUMBER_ONLY_THE_HOST_KNOWS}));\n':
        '2S\n',
}


def _the_label_a_body_reports(host: Node) -> str:
    """
    The label the body at *host* prints its own mode under. The search stops at every body written
    inside that one, which is what leaves a nested body its own label rather than the label of the
    body it stands in.
    """
    labels: set[str] = set()
    stack = list(host.children())
    while stack:
        node = stack.pop()
        if is_prologue_host(node):
            continue
        if isinstance(node, JsStringLiteral) and '=' in node.body:
            labels.add(node.body.partition('=')[0])
        stack.extend(node.children())
    label, = labels
    return label


def _the_modes_the_audit_reads(source: str) -> dict[str, bool]:
    return {
        _the_label_a_body_reports(node): strict
        for node, strict in mode_of_every_body(JsParser(source).parse()).values()
    }


def _the_modes_node_prints(source: str, *, module: bool = False) -> dict[str, bool]:
    printed, error = behavior(source, module=module)
    if error is not None:
        raise AssertionError(F'node refused the program: {error}')
    return {
        label: reported == 'true'
        for label, _, reported in (line.partition('=') for line in printed.splitlines())
    }


def _after_the_edit(edit: type[Transformer], source: str) -> tuple[StrictModeAudit, str]:
    """
    The audit of a run of *edit* over *source*, and the text that run leaves behind.
    """
    ast = JsParser(source).parse()
    audit = StrictModeAudit()
    TransformerGroup(_THE_GROUP, edit).run(ast, observer=audit)
    return audit, JsSynthesizer().convert(ast)


def _the_bodies_the_audit_names(audit: StrictModeAudit) -> dict[str, bool]:
    """
    Every body the audit named, by the label it prints under, mapped to the mode it now runs in.
    """
    named: dict[str, bool] = {}
    for movement in audit.movements:
        for node in movement.became_strict:
            named[_the_label_a_body_reports(node)] = True
        for node in movement.became_sloppy:
            named[_the_label_a_body_reports(node)] = False
    return named


def _the_bodies_node_compiles_differently(before: str, after: str) -> dict[str, bool]:
    """
    Every body both texts print, whose mode differs between the two, mapped to the mode it runs in
    afterwards. A body only one of them prints is no such body: it ran in no mode on the other side.
    """
    was, now = _the_modes_node_prints(before), _the_modes_node_prints(after)
    return {
        label: now[label]
        for label in was.keys() & now.keys()
        if was[label] != now[label]
    }


def _audited(source: str) -> str:
    ast = JsParser(source).parse()
    audit = StrictModeAudit()
    deobfuscate(ast, observer=audit)
    return audit.report()


def _before_and_after(source: str) -> tuple[tuple[str, str | None], tuple[str, str | None]]:
    return behavior(source), behavior(deobfuscate_source(source))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodeCompilesEveryBodyInTheModeTheCorpusRecords(TestBase):

    def test_every_body_of_a_script_prints_the_mode_the_corpus_records(self):
        rows = A_PROGRAM_WHOSE_EVERY_BODY_REPORTS_ITS_MODE
        self.assertEqual(
            {source: _the_modes_node_prints(source) for source in rows},
            dict(rows),
        )

    def test_every_body_of_a_module_prints_strict(self):
        rows = A_MODULE_WHOSE_EVERY_BODY_REPORTS_ITS_MODE
        self.assertEqual(
            {source: _the_modes_node_prints(source, module=True) for source in rows},
            dict(rows),
        )


class TestTheAuditReadsTheModeEveryBodyRunsIn(TestBase):

    def test_it_reads_the_mode_the_corpus_records_for_every_body_of_every_program(self):
        rows = {
            **A_PROGRAM_WHOSE_EVERY_BODY_REPORTS_ITS_MODE,
            **A_MODULE_WHOSE_EVERY_BODY_REPORTS_ITS_MODE,
        }
        self.assertEqual(
            {source: _the_modes_the_audit_reads(source) for source in rows},
            dict(rows),
        )


class TestTheAuditNamesEveryBodyThatCameOutInTheOtherMode(TestBase):

    def test_it_names_the_bodies_the_corpus_records_and_the_mode_each_now_runs_in(self):
        rows = AN_EDIT_AND_THE_BODIES_IT_LEAVES_IN_THE_OTHER_MODE
        self.assertEqual(
            {
                edit: _the_bodies_the_audit_names(_after_the_edit(edit, source)[0])
                for edit, (source, _) in rows.items()
            },
            {edit: moved for edit, (_, moved) in rows.items()},
        )

    def test_it_attributes_every_one_of_them_to_the_pass_that_ran(self):
        rows = AN_EDIT_AND_THE_BODIES_IT_LEAVES_IN_THE_OTHER_MODE
        self.assertEqual(
            {
                edit: [
                    (movement.group, movement.transformer)
                    for movement in _after_the_edit(edit, source)[0].movements
                ]
                for edit, (source, _) in rows.items()
            },
            {
                edit: [(_THE_GROUP, edit.__name__)] if moved else []
                for edit, (_, moved) in rows.items()
            },
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_compiles_exactly_those_bodies_differently_after_the_edit(self):
        rows = AN_EDIT_AND_THE_BODIES_IT_LEAVES_IN_THE_OTHER_MODE
        self.assertEqual(
            {
                edit: _the_bodies_node_compiles_differently(
                    source, _after_the_edit(edit, source)[1])
                for edit, (source, _) in rows.items()
            },
            {edit: moved for edit, (_, moved) in rows.items()},
        )


class TestAPassThatAddsOrRemovesAStrictBodyMovesNoMode(TestBase):

    def test_the_audit_reports_nothing_over_any_of_those_programs(self):
        rows = A_PROGRAM_A_PASS_ADDS_OR_REMOVES_A_STRICT_BODY_IN
        self.assertEqual(
            {source: _audited(source) for source in rows},
            {source: '' for source in rows},
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_prints_the_same_for_each_of_them_and_for_its_deobfuscation(self):
        rows = A_PROGRAM_A_PASS_ADDS_OR_REMOVES_A_STRICT_BODY_IN
        self.assertEqual(
            {source: _before_and_after(source) for source in rows},
            {source: ((printed, None), (printed, None)) for source, printed in rows.items()},
        )


class TestTheAuditReportsNothingOverAProgramWhoseModesAreAlreadyPinned(TestBase):
    """
    The corpus is `test.lib.scripts.js.test_directive_prologue.A_PROGRAM_REPORTING_ITS_MODE`, where
    every program is pinned to print what it printed before once it has been deobfuscated. What a
    program prints is the mode of the bodies it runs; what the audit reads is the mode of every body
    it has, run or not, and after every pass rather than only at the end.
    """

    def test_it_reports_nothing_over_any_of_them(self):
        rows = A_PROGRAM_REPORTING_ITS_MODE
        self.assertEqual(
            {source: _audited(source) for source in rows},
            {source: '' for source in rows},
        )


class ATransformerThatRaisesHalfwayThroughTheBody(Transformer):
    """
    Drops the directive from a body that holds one and then raises, which is what a pass does that
    edits and then fails: the tree is left in a state no pass ever chose to produce.
    """

    def visit_JsFunctionDeclaration(self, node: JsFunctionDeclaration):
        body = node.body
        if not isinstance(body, JsBlockStatement):
            return
        set_body(body, [
            statement for statement in body.body
            if not is_use_strict_directive(statement)
        ])
        raise ZeroDivisionError('the pass failed after editing')


class TestAPassThatRaisesIsNoReadingTheAuditKeeps(TestBase):
    """
    A tree a transformer left behind on its way out is not that pass's result, so no mode read from
    it may be reported, and the reading taken before it may not survive to be compared against the
    next pass. This transformer moves a mode and then raises, which is the one shape that tells the
    two apart: an audit that reported from the half-edited tree would name it, and one that kept the
    reading would compare the next pass against a tree that no longer exists.
    """

    def test_it_names_no_movement(self):
        source = F"function f() {{ 'use strict'; {_reports('f')} }}"
        ast = JsParser(source).parse()
        audit = StrictModeAudit()
        with self.assertRaises(ZeroDivisionError):
            TransformerGroup(_THE_GROUP, ATransformerThatRaisesHalfwayThroughTheBody).run(
                ast, observer=audit)
        self.assertEqual(audit.report(), '')

    def test_the_reading_it_was_measured_against_is_not_compared_against_the_next_pass(self):
        source = F"function f() {{ 'use strict'; {_reports('f')} }}"
        ast = JsParser(source).parse()
        audit = StrictModeAudit()
        raising = ATransformerThatRaisesHalfwayThroughTheBody
        audit.before(_THE_GROUP, raising, ast)
        with self.assertRaises(ZeroDivisionError):
            raising().visit(ast)
        audit.failed(_THE_GROUP, raising)
        audit.after(_THE_GROUP, TheDirectiveSweptOutOfTheBody, ast, False)
        self.assertEqual(audit.report(), '')
