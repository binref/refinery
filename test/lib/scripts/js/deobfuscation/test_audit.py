"""
SECURITY: Node runs every snippet here. Each is written by hand and benign; nothing from `samples`
may ever be fed to this module.
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
    A statement printing, under *label*, whether the code it stands in is strict: `NaN` is a
    read-only property of the global object, so assigning to it throws a `TypeError` in strict code
    and does nothing in sloppy code.
    """
    return (
        F"try {{ NaN = 1; console.log('{label}=false'); }}"
        F" catch (e) {{ console.log('{label}=true'); }}"
    )


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

A_MODULE_WHOSE_EVERY_BODY_REPORTS_ITS_MODE = {
    F"export {{}};\n{_reports('top')}\nfunction f() {{ {_reports('f')} }}\nf();\n": {
        'top' : True,
        'f'   : True,
    },
}

A_STRICT_FUNCTION_IN_A_SLOPPY_SCRIPT = (
    F"{_reports('top')}\nfunction f() {{ 'use strict'; {_reports('f')} }}\nf();\n"
)


class ADeclarationWrittenAboveTheDirective(Transformer):
    """
    The directive is left in place but stops being one: a Directive Prologue is the run of string
    literals a body opens with.
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

_THE_MODE_IT_STANDS_IN = '(function () { return this; })() === undefined'

#: A number the tool cannot compute and Node answers with `2`.
_A_NUMBER_ONLY_THE_HOST_KNOWS = 'process.argv.length'


def _returns_the_mode_it_stands_in(value: str) -> str:
    return F"return {value} + ({_THE_MODE_IT_STANDS_IN} ? 'S' : 'L');"


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
    ast = JsParser(source).parse()
    audit = StrictModeAudit()
    TransformerGroup(_THE_GROUP, edit).run(ast, observer=audit)
    return audit, JsSynthesizer().convert(ast)


def _the_bodies_the_audit_names(audit: StrictModeAudit) -> dict[str, bool]:
    named: dict[str, bool] = {}
    for movement in audit.movements:
        for node in movement.became_strict:
            named[_the_label_a_body_reports(node)] = True
        for node in movement.became_sloppy:
            named[_the_label_a_body_reports(node)] = False
    return named


def _the_bodies_node_compiles_differently(before: str, after: str) -> dict[str, bool]:
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

    def test_it_reports_nothing_over_any_of_them(self):
        rows = A_PROGRAM_REPORTING_ITS_MODE
        self.assertEqual(
            {source: _audited(source) for source in rows},
            {source: '' for source in rows},
        )


class ATransformerThatRaisesHalfwayThroughTheBody(Transformer):

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


class TestARunWhoseResultMayBeDiscardedReportsThroughAFork(TestBase):

    @staticmethod
    def _forked_run(audit: StrictModeAudit):
        fork = audit.fork()
        ast = JsParser(A_STRICT_FUNCTION_IN_A_SLOPPY_SCRIPT).parse()
        TransformerGroup(_THE_GROUP, TheDirectiveSweptOutOfTheBody).run(ast, observer=fork)
        return fork

    def test_a_fork_that_is_not_merged_leaves_the_report_empty(self):
        audit = StrictModeAudit()
        self._forked_run(audit)
        self.assertEqual(audit.report(), '')

    def test_a_merged_fork_reports_what_it_saw(self):
        audit = StrictModeAudit()
        audit.merge(self._forked_run(audit))
        self.assertEqual(
            [(movement.group, movement.transformer) for movement in audit.movements],
            [(_THE_GROUP, TheDirectiveSweptOutOfTheBody.__name__)],
        )
