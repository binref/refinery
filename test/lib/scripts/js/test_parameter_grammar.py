"""
What the language refuses about a function's signature, and whether the tool refuses the same texts.

Which rules apply depends on where a function stands rather than on the function: a repeated
parameter name is read in a sloppy function expression standing as a property value and refused in a
method.

SECURITY: every snippet here is hand-authored and benign, and Node runs it. Nothing from `samples`
may ever be fed to this.
"""
from __future__ import annotations

import unittest

from typing import Iterable, NamedTuple, Sequence

from test import TestBase
from test.lib.scripts.js.analysis.differential import (
    JsEvaluation,
    behavior,
    completion_values,
    node_executable,
)
from test.lib.scripts.js.ledger import each_well_formed
from test.lib.scripts.js.test_directive_prologue import (
    A_FUNCTION_WRITTEN_AS,
    A_PARAMETER_LIST,
    NOT_A_PROGRAM,
)

from refinery.lib.scripts.js.model import (
    JsArrowFunctionExpression,
    JsFunctionDeclaration,
    JsFunctionExpression,
)
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.strict import (
    ParameterGrammar,
    collect_strict_violations,
    parameter_grammar,
)
from refinery.lib.scripts.js.synth import JsSynthesizer

_FUNCTION_NODES = (JsFunctionDeclaration, JsFunctionExpression, JsArrowFunctionExpression)


class APosition(NamedTuple):
    template: str
    grammar: ParameterGrammar
    refuses_a_repeated_name: bool


#: A function expression in a class field refuses a repeated name although it reads its parameters
#: as a plain function does, because every part of a class is strict code.
A_FUNCTION_STANDING_AS = {
    'a function declaration': APosition(
        'function f({params}) {{ {body} }}', ParameterGrammar.FORMAL, False),
    'a function expression': APosition(
        'var f = function ({params}) {{ {body} }};', ParameterGrammar.FORMAL, False),
    'a named function expression': APosition(
        'var f = function g({params}) {{ {body} }};', ParameterGrammar.FORMAL, False),
    'a generator declaration': APosition(
        'function* g({params}) {{ {body} }}', ParameterGrammar.FORMAL, False),
    'an async function declaration': APosition(
        'async function h({params}) {{ {body} }}', ParameterGrammar.FORMAL, False),
    'the value of a property': APosition(
        'var o = {{ m: function ({params}) {{ {body} }} }};', ParameterGrammar.FORMAL, False),
    'the value of a property named get': APosition(
        'var o = {{ get: function ({params}) {{ {body} }} }};', ParameterGrammar.FORMAL, False),
    'the value of a property named set': APosition(
        'var o = {{ set: function ({params}) {{ {body} }} }};', ParameterGrammar.FORMAL, False),
    'the value of a class field': APosition(
        'class C {{ p = function ({params}) {{ {body} }}; }}', ParameterGrammar.FORMAL, True),
    'an arrow': APosition(
        'var f = ({params}) => {{ {body} }};', ParameterGrammar.UNIQUE, True),
    'an async arrow': APosition(
        'var f = async ({params}) => {{ {body} }};', ParameterGrammar.UNIQUE, True),
    'an arrow as the value of a property': APosition(
        'var o = {{ m: ({params}) => {{ {body} }} }};', ParameterGrammar.UNIQUE, True),
    'an arrow as a class field': APosition(
        'class C {{ p = ({params}) => {{ {body} }}; }}', ParameterGrammar.UNIQUE, True),
    'an object method': APosition(
        'var o = {{ m({params}) {{ {body} }} }};', ParameterGrammar.UNIQUE, True),
    'an object method named get': APosition(
        'var o = {{ get({params}) {{ {body} }} }};', ParameterGrammar.UNIQUE, True),
    'an object method named set': APosition(
        'var o = {{ set({params}) {{ {body} }} }};', ParameterGrammar.UNIQUE, True),
    'a computed object method': APosition(
        "var o = {{ ['m']({params}) {{ {body} }} }};", ParameterGrammar.UNIQUE, True),
    'an object generator method': APosition(
        'var o = {{ *m({params}) {{ {body} }} }};', ParameterGrammar.UNIQUE, True),
    'an async object method': APosition(
        'var o = {{ async m({params}) {{ {body} }} }};', ParameterGrammar.UNIQUE, True),
    'a class method': APosition(
        'class C {{ m({params}) {{ {body} }} }}', ParameterGrammar.UNIQUE, True),
    'a static class method': APosition(
        'class C {{ static m({params}) {{ {body} }} }}', ParameterGrammar.UNIQUE, True),
    'a class method named get': APosition(
        'class C {{ get({params}) {{ {body} }} }}', ParameterGrammar.UNIQUE, True),
    'a private class method': APosition(
        'class C {{ #m({params}) {{ {body} }} }}', ParameterGrammar.UNIQUE, True),
    'a class generator method': APosition(
        'class C {{ *m({params}) {{ {body} }} }}', ParameterGrammar.UNIQUE, True),
    'a class constructor': APosition(
        'class C {{ constructor({params}) {{ {body} }} }}', ParameterGrammar.UNIQUE, True),
}

A_GETTER_STANDING_AS = {
    'an object getter'         : 'var o = {{ get g({params}) {{ {body} }} }};',
    'a computed object getter' : "var o = {{ get ['g']({params}) {{ {body} }} }};",
    'a class getter'           : 'class C {{ get g({params}) {{ {body} }} }}',
    'a static class getter'    : 'class C {{ static get g({params}) {{ {body} }} }}',
    'a private class getter'   : 'class C {{ get #g({params}) {{ {body} }} }}',
}

A_SETTER_STANDING_AS = {
    'an object setter'         : 'var o = {{ set s({params}) {{ {body} }} }};',
    'a computed object setter' : "var o = {{ set ['s']({params}) {{ {body} }} }};",
    'a class setter'           : 'class C {{ set s({params}) {{ {body} }} }}',
    'a static class setter'    : 'class C {{ static set s({params}) {{ {body} }} }}',
    'a private class setter'   : 'class C {{ set #s({params}) {{ {body} }} }}',
}

A_LIST_THE_POSITION_PERMITS = 'a'
A_LIST_A_GETTER_PERMITS = ''
A_LIST_A_SETTER_PERMITS = 'v'

#: A parameter list holding one name twice, mapped to whether a sloppy plain function refuses it: it
#: does once the list holds a default, a rest element or a pattern anywhere, even away from the
#: repeated name.
A_PARAMETER_LIST_HOLDING_A_REPEATED_NAME = {
    'a, a'        : False,
    'a, b, a'     : False,
    'a, a, a'     : False,
    'a, a, b = 1' : True,
    'a = 1, a'    : True,
    'a, ...a'     : True,
    '[a, a]'      : True,
    '{a, b: a}'   : True,
    '{a}, a'      : True,
    'a, [a]'      : True,
}

A_LIST_A_GETTER_MAY_TAKE = {
    ''      : True,
    'a'     : False,
    'a, b'  : False,
    'a,'    : False,
    '...a'  : False,
    'a = 1' : False,
    '[a]'   : False,
    '{a}'   : False,
}

#: A setter takes exactly one parameter, which may be a default or a pattern but not a rest element.
A_LIST_A_SETTER_MAY_TAKE = {
    ''      : False,
    'a'     : True,
    'a, b'  : False,
    'a,'    : True,
    '...a'  : False,
    'a = 1' : True,
    '[a]'   : True,
    '{a}'   : True,
}

#: A function body, mapped to whether it declares the Use Strict Directive: a `'use strict'` written
#: without parentheses or escapes among the string literal statements that open the body.
A_FUNCTION_BODY_WRITTEN_AS = {
    ''                            : False,
    "'use strict';"               : True,
    "'use strict'"                : True,
    "('use strict');"             : False,
    "'other'; 'use strict';"      : True,
    "0; 'use strict';"            : False,
    '`use strict`;'               : False,
    R"'use\u0020strict';"         : False,
    "'use strict'; 'use strict';" : True,
}

A_LIST_THAT_IS_NOT_SIMPLE = 'a = 1'
A_LIST_THAT_IS_SIMPLE = 'a'

AN_ACCESSOR_HOLDING_THE_DIRECTIVE = {
    "var o = { get g() { 'use strict'; } };"          : False,
    "var o = { set s(v) { 'use strict'; } };"         : False,
    "var o = { set s(v = 1) { 'use strict'; } };"     : True,
    "var o = { set s([v]) { 'use strict'; } };"       : True,
    "var o = { set s({v}) { 'use strict'; } };"       : True,
    "class C { get g() { 'use strict'; } }"           : False,
    "class C { set s(v = 1) { 'use strict'; } }"      : True,
    "class C { static set s([v]) { 'use strict'; } }" : True,
}

AN_ARROW_WHOSE_BODY_IS_AN_EXPRESSION = [
    "var f = (a = 1) => 'use strict';",
    "var f = (a = 1) => ('use strict');",
    "var f = ([a]) => 'use strict';",
    "var f = (...a) => 'use strict';",
]

#: Each rule applies to its own signature: the repeat in the inner list is legal unless the inner
#: body is strict, and the outer body may hold no directive because the outer list is not simple.
A_FUNCTION_WRITTEN_INTO_ANOTHERS_PARAMETER_LIST = {
    'function f(a = function (b, b) {}) {}'                : False,
    'function f(a = function (b) {}) {}'                   : False,
    "function f(a = function (b, b) { 'use strict'; }) {}" : True,
    "function f(a = function (b, b) {}) { 'use strict'; }" : True,
    "function f(a = function (b) {}) { 'use strict'; }"    : True,
}

A_REPEATED_NAME_MADE_AN_ERROR_BY = {
    'function f(a, a) {}'                                 : False,
    "function f(a, a) { 'use strict'; }"                  : True,
    "function f(a, a) { 'other'; 'use strict'; }"         : True,
    "function f(a, a) { 0; 'use strict'; }"               : False,
    "function f(a, a) { ('use strict'); }"                : False,
    "function f(a, a) { function g() { 'use strict'; } }" : False,
    "function f() { 'use strict'; function g(a, a) {} }"  : True,
    'class C { m() { function g(a, a) {} } }'             : True,
    'var o = { m: function (a, a) {} };'                  : False,
    'var o = { m(a, a) {} };'                             : True,
    'var f = (a, a) => {};'                               : True,
}

A_NAME_THE_KIND_OF_FUNCTION_RESERVES = [
    'function* g(yield) {}',
    'function* g(a = yield) {}',
    'function* g() { var yield = 1; }',
    'var o = { *m(yield) {} };',
    'async function h(await) {}',
    'var f = async (await) => {};',
    'var o = { async m(await) {} };',
]

A_NAME_THE_PARSER_REFUSES_TO_READ = [
    'async function h(a = await) {}',
]

A_BINDING_THE_KIND_OF_FUNCTION_RESERVES = [
    'function* g() { function yield() {} }',
    'function* g() { class yield {} }',
    'async function h() { function await() {} }',
    'async function h() { class await {} }',
]

#: `class yield {}` is refused even here, because a class name is strict code and strict code
#: reserves `yield`, but not `await`.
THE_SAME_BINDING_INSIDE_A_PLAIN_FUNCTION = {
    'function g() { function yield() {} }' : False,
    'function g() { class yield {} }'      : True,
    'function h() { function await() {} }' : False,
    'function h() { class await {} }'      : False,
}

A_FUNCTION_EXPRESSION_NAMED_BY_A_WORD_ITS_OWN_KIND_RESERVES = [
    'var x = function* yield() {};',
    'var x = (function* yield() {});',
    'var x = async function await() {};',
    'var o = { m: function* yield() {} };',
    'var o = { m: async function await() {} };',
    'function p() { var f = function* yield() {}; }',
    'function p() { var f = async function await() {}; }',
]

A_FUNCTION_EXPRESSION_NAME_ITS_OWN_KIND_LEAVES_ALONE = [
    'var x = function yield() {};',
    'var x = function await() {};',
    'var x = async function yield() {};',
    'var x = function* await() {};',
]

A_DECLARATION_WHOSE_NAME_THE_ENCLOSING_CONTEXT_GOVERNS = [
    'function* yield() {}',
    'async function await() {}',
    'function p() { function* yield() {} }',
    'function p() { async function await() {} }',
]

A_FUNCTION_EXPRESSION_NAME_ONLY_THE_ENCLOSING_KIND_RESERVES = [
    'function* g() { var f = function yield() { return 1; }; }',
    'async function h() { var f = function await() { return 1; }; }',
    'var o = { *m() { var f = function yield() { return 1; }; } };',
    'var o = { async m() { var f = function await() { return 1; }; } };',
    'function* g() { (function yield() { return 1; })(); }',
    "'use strict'; async function h() { var f = function await() { return 1; }; }",
]

A_CLASS_EXPRESSION_NAME_THE_ENCLOSING_KIND_RESERVES = [
    'function* g() { var C = class yield {}; }',
    'async function h() { var C = class await {}; }',
    'var o = { *m() { var C = class yield {}; } };',
    'var o = { async m() { var C = class await {}; } };',
]


def _a_repeated_name_in_every_position() -> dict[str, bool]:
    return {
        position.template.format(params=params, body=''):
            position.refuses_a_repeated_name or refused_by_formal_parameters
        for position in A_FUNCTION_STANDING_AS.values()
        for params, refused_by_formal_parameters
        in A_PARAMETER_LIST_HOLDING_A_REPEATED_NAME.items()
    }


def _every_body_under(params: str) -> dict[str, bool]:
    return {
        position.template.format(params=params, body=body): declares
        for position in A_FUNCTION_STANDING_AS.values()
        for body, declares in A_FUNCTION_BODY_WRITTEN_AS.items()
    }


def _every_list_in(positions: Iterable[str], lists: dict[str, bool]) -> dict[str, bool]:
    return {
        template.format(params=params, body=''): not permitted
        for template in positions
        for params, permitted in lists.items()
    }


def _under_a_strict_seed(source: str) -> str:
    return F"'use strict';\n{source}"


def refused(programs: Sequence[str]) -> dict[str, bool]:
    """
    Whether Node refuses to read each of *programs* at all. Each is compiled in a context of its
    own, so one refusal says nothing about the others.
    """
    return {
        program: value == NOT_A_PROGRAM
        for program, value in zip(programs, completion_values(programs, JsEvaluation.SCRIPT))
    }


def reported(programs: Iterable[str], *, strict: bool) -> dict[str, bool]:
    return {
        program: bool(collect_strict_violations(JsParser(program).parse(), strict=strict))
        for program in programs
    }


def _refused_under_a_strict_seed(programs: Iterable[str]) -> dict[str, bool]:
    return refused([_under_a_strict_seed(program) for program in programs])


def every_one_of(programs: Iterable[str], answer: bool) -> dict[str, bool]:
    return {program: answer for program in programs}


def _the_function_written_as(
    template: str,
    params: str,
) -> JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression:
    function, = (
        node for node in JsParser(template.format(params=params, body='')).parse().walk()
        if isinstance(node, _FUNCTION_NODES)
    )
    return function


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestWhereNodeRefusesARepeatedParameterName(TestBase):

    def test_node_refuses_each_position_the_corpus_records(self):
        rows = _a_repeated_name_in_every_position()
        self.assertEqual(refused(list(rows)), rows)

    def test_a_strict_file_refuses_a_repeated_name_in_every_position(self):
        rows = _a_repeated_name_in_every_position()
        strict = [_under_a_strict_seed(program) for program in rows]
        self.assertEqual(refused(strict), every_one_of(strict, True))

    def test_node_reads_every_one_of_those_positions_with_no_name_repeated(self):
        rows = [
            position.template.format(params=params, body='')
            for position in A_FUNCTION_STANDING_AS.values()
            for params in A_PARAMETER_LIST
        ]
        self.assertEqual(refused(rows), every_one_of(rows, False))


class TestTheCollectorReportsARepeatedParameterNameWhereNodeDoes(TestBase):

    def test_it_reports_on_exactly_the_positions_a_sloppy_file_refuses(self):
        rows = _a_repeated_name_in_every_position()
        self.assertEqual(reported(rows, strict=False), rows)

    def test_it_reports_on_every_position_under_a_strict_seed(self):
        rows = _a_repeated_name_in_every_position()
        self.assertEqual(reported(rows, strict=True), every_one_of(rows, True))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestWhichParameterListsAnAccessorMayBeWrittenWith(TestBase):

    def test_node_refuses_each_getter_the_corpus_records(self):
        rows = _every_list_in(A_GETTER_STANDING_AS.values(), A_LIST_A_GETTER_MAY_TAKE)
        self.assertEqual(refused(list(rows)), rows)

    def test_node_refuses_each_setter_the_corpus_records(self):
        rows = _every_list_in(A_SETTER_STANDING_AS.values(), A_LIST_A_SETTER_MAY_TAKE)
        self.assertEqual(refused(list(rows)), rows)

    def test_a_strict_file_refuses_and_reads_the_same_accessors(self):
        rows = {
            **_every_list_in(A_GETTER_STANDING_AS.values(), A_LIST_A_GETTER_MAY_TAKE),
            **_every_list_in(A_SETTER_STANDING_AS.values(), A_LIST_A_SETTER_MAY_TAKE),
        }
        self.assertEqual(
            _refused_under_a_strict_seed(rows),
            {_under_a_strict_seed(program): refused for program, refused in rows.items()},
        )


class TestTheCollectorReportsAnAccessorsArityWhereNodeDoes(TestBase):

    def test_it_reports_on_exactly_the_getters_node_refuses(self):
        rows = _every_list_in(A_GETTER_STANDING_AS.values(), A_LIST_A_GETTER_MAY_TAKE)
        self.assertEqual(reported(rows, strict=False), rows)

    def test_it_reports_on_exactly_the_setters_node_refuses(self):
        rows = _every_list_in(A_SETTER_STANDING_AS.values(), A_LIST_A_SETTER_MAY_TAKE)
        self.assertEqual(reported(rows, strict=False), rows)

    def test_the_seeded_mode_moves_no_accessor(self):
        rows = {
            **_every_list_in(A_GETTER_STANDING_AS.values(), A_LIST_A_GETTER_MAY_TAKE),
            **_every_list_in(A_SETTER_STANDING_AS.values(), A_LIST_A_SETTER_MAY_TAKE),
        }
        self.assertEqual(reported(rows, strict=True), rows)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestWhereADirectiveMayStandUnderAParameterList(TestBase):

    def test_node_refuses_a_body_that_declares_one_under_a_list_that_is_not_simple(self):
        rows = _every_body_under(A_LIST_THAT_IS_NOT_SIMPLE)
        self.assertEqual(refused(list(rows)), rows)

    def test_node_reads_every_one_of_those_bodies_under_a_list_that_is_simple(self):
        rows = _every_body_under(A_LIST_THAT_IS_SIMPLE)
        self.assertEqual(refused(list(rows)), every_one_of(rows, False))

    def test_a_strict_file_refuses_the_same_bodies(self):
        rows = _every_body_under(A_LIST_THAT_IS_NOT_SIMPLE)
        self.assertEqual(
            _refused_under_a_strict_seed(rows),
            {_under_a_strict_seed(program): declares for program, declares in rows.items()},
        )

    def test_node_decides_each_accessor_the_corpus_records(self):
        rows = AN_ACCESSOR_HOLDING_THE_DIRECTIVE
        self.assertEqual(refused(list(rows)), dict(rows))

    def test_node_reads_an_arrow_whose_body_is_an_expression(self):
        rows = AN_ARROW_WHOSE_BODY_IS_AN_EXPRESSION
        self.assertEqual(refused(rows), every_one_of(rows, False))

    def test_node_decides_each_nested_function_the_corpus_records(self):
        rows = A_FUNCTION_WRITTEN_INTO_ANOTHERS_PARAMETER_LIST
        self.assertEqual(refused(list(rows)), dict(rows))


class TestTheCollectorReportsADirectiveWhereNodeRefusesOne(TestBase):

    def test_it_reports_on_exactly_the_bodies_that_declare_one(self):
        rows = _every_body_under(A_LIST_THAT_IS_NOT_SIMPLE)
        self.assertEqual(reported(rows, strict=False), rows)

    def test_it_reports_on_none_of_them_under_a_list_that_is_simple(self):
        rows = _every_body_under(A_LIST_THAT_IS_SIMPLE)
        self.assertEqual(reported(rows, strict=False), every_one_of(rows, False))

    def test_the_seeded_mode_moves_no_body(self):
        rows = _every_body_under(A_LIST_THAT_IS_NOT_SIMPLE)
        self.assertEqual(reported(rows, strict=True), rows)

    def test_it_reports_on_exactly_the_accessors_node_refuses(self):
        rows = AN_ACCESSOR_HOLDING_THE_DIRECTIVE
        self.assertEqual(reported(rows, strict=False), dict(rows))

    def test_it_reports_on_no_arrow_whose_body_is_an_expression(self):
        rows = AN_ARROW_WHOSE_BODY_IS_AN_EXPRESSION
        self.assertEqual(reported(rows, strict=False), every_one_of(rows, False))

    def test_it_reports_on_exactly_the_nested_functions_node_refuses(self):
        rows = A_FUNCTION_WRITTEN_INTO_ANOTHERS_PARAMETER_LIST
        self.assertEqual(reported(rows, strict=False), dict(rows))


class TestWhichShapesADirectiveIsPermittedUnderAreTheSameOnesTheCollectorReads(TestBase):

    def test_the_collector_reports_on_a_directive_under_every_list_that_is_not_simple(self):
        for shape, template in A_FUNCTION_WRITTEN_AS.items():
            rows = {
                template.format(params=params, body="'use strict';"): not simple
                for params, simple in A_PARAMETER_LIST.items()
            }
            with self.subTest(shape=shape):
                self.assertEqual(reported(rows, strict=False), rows)

    def test_the_collector_reports_on_none_of_those_lists_with_an_empty_body(self):
        for shape, template in A_FUNCTION_WRITTEN_AS.items():
            rows = [template.format(params=params, body='') for params in A_PARAMETER_LIST]
            with self.subTest(shape=shape):
                self.assertEqual(reported(rows, strict=False), every_one_of(rows, False))


class TestWhichGrammarAFunctionTakesItsParametersThrough(TestBase):

    def test_a_function_takes_the_grammar_the_position_it_stands_in_records(self):
        self.assertEqual(
            {
                name: parameter_grammar(
                    _the_function_written_as(position.template, A_LIST_THE_POSITION_PERMITS))
                for name, position in A_FUNCTION_STANDING_AS.items()
            },
            {name: position.grammar for name, position in A_FUNCTION_STANDING_AS.items()},
        )

    def test_a_getter_takes_the_getter_grammar_wherever_it_stands(self):
        self.assertEqual(
            {
                name: parameter_grammar(
                    _the_function_written_as(template, A_LIST_A_GETTER_PERMITS))
                for name, template in A_GETTER_STANDING_AS.items()
            },
            {name: ParameterGrammar.GETTER for name in A_GETTER_STANDING_AS},
        )

    def test_a_setter_takes_the_setter_grammar_wherever_it_stands(self):
        self.assertEqual(
            {
                name: parameter_grammar(
                    _the_function_written_as(template, A_LIST_A_SETTER_PERMITS))
                for name, template in A_SETTER_STANDING_AS.items()
            },
            {name: ParameterGrammar.SETTER for name in A_SETTER_STANDING_AS},
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestWhereTheStrictnessThatRefusesARepeatedNameComesFrom(TestBase):

    def test_node_decides_each_file_the_corpus_records(self):
        rows = A_REPEATED_NAME_MADE_AN_ERROR_BY
        self.assertEqual(refused(list(rows)), dict(rows))


class TestTheCollectorReadsTheStrictnessFromTheSamePlace(TestBase):

    def test_it_reports_on_exactly_the_files_node_refuses(self):
        rows = A_REPEATED_NAME_MADE_AN_ERROR_BY
        self.assertEqual(reported(rows, strict=False), dict(rows))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestANameTheKindOfFunctionReserves(TestBase):

    def test_node_refuses_every_one_of_them_as_a_sloppy_file(self):
        rows = [*A_NAME_THE_KIND_OF_FUNCTION_RESERVES, *A_NAME_THE_PARSER_REFUSES_TO_READ]
        self.assertEqual(refused(rows), every_one_of(rows, True))

    def test_node_refuses_every_one_of_them_as_a_strict_file(self):
        rows = [*A_NAME_THE_KIND_OF_FUNCTION_RESERVES, *A_NAME_THE_PARSER_REFUSES_TO_READ]
        self.assertEqual(
            _refused_under_a_strict_seed(rows),
            every_one_of([_under_a_strict_seed(program) for program in rows], True),
        )

    def test_node_refuses_the_same_word_used_to_name_a_declaration(self):
        rows = A_BINDING_THE_KIND_OF_FUNCTION_RESERVES
        self.assertEqual(refused(rows), every_one_of(rows, True))

    def test_node_reads_those_declarations_inside_a_function_of_no_reserving_kind(self):
        rows = THE_SAME_BINDING_INSIDE_A_PLAIN_FUNCTION
        self.assertEqual(refused(list(rows)), dict(rows))


class TestTheCollectorReportsANameTheKindOfFunctionReserves(TestBase):

    def test_it_reports_on_every_name_node_refuses_under_a_sloppy_seed(self):
        rows = A_NAME_THE_KIND_OF_FUNCTION_RESERVES
        self.assertEqual(reported(rows, strict=False), every_one_of(rows, True))

    def test_it_reports_on_every_one_of_them_under_a_strict_seed(self):
        rows = A_NAME_THE_KIND_OF_FUNCTION_RESERVES
        self.assertEqual(reported(rows, strict=True), every_one_of(rows, True))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestWhichContextGovernsAFunctionsOwnName(TestBase):
    """
    A function expression's name is read under the expression's own kind, a declaration's under the
    code around it: in sloppy code, `function* yield() {}` is refused as an expression and read as a
    declaration.
    """

    def test_node_refuses_every_expression_named_by_a_word_its_own_kind_reserves(self):
        rows = A_FUNCTION_EXPRESSION_NAMED_BY_A_WORD_ITS_OWN_KIND_RESERVES
        self.assertEqual(refused(rows), every_one_of(rows, True))

    def test_node_refuses_them_under_a_strict_seed_too(self):
        rows = A_FUNCTION_EXPRESSION_NAMED_BY_A_WORD_ITS_OWN_KIND_RESERVES
        self.assertEqual(
            _refused_under_a_strict_seed(rows),
            every_one_of([_under_a_strict_seed(program) for program in rows], True),
        )

    def test_node_reads_an_expression_whose_own_kind_reserves_neither_word(self):
        rows = A_FUNCTION_EXPRESSION_NAME_ITS_OWN_KIND_LEAVES_ALONE
        self.assertEqual(refused(rows), every_one_of(rows, False))

    def test_node_reads_the_same_word_naming_a_declaration(self):
        rows = A_DECLARATION_WHOSE_NAME_THE_ENCLOSING_CONTEXT_GOVERNS
        self.assertEqual(refused(rows), every_one_of(rows, False))

    def test_node_reads_an_expression_only_the_kind_around_it_reserves_the_name_of(self):
        rows = A_FUNCTION_EXPRESSION_NAME_ONLY_THE_ENCLOSING_KIND_RESERVES
        self.assertEqual(refused(rows), every_one_of(rows, False))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestWhichContextGovernsAClassExpressionsOwnName(TestBase):
    """
    Unlike a function expression's name, a class expression's name is read under the code around it:
    inside an async function, `class await {}` is refused where `function await() {}` is read.
    """

    def test_node_refuses_every_class_expression_the_kind_around_it_reserves_the_name_of(self):
        rows = A_CLASS_EXPRESSION_NAME_THE_ENCLOSING_KIND_RESERVES
        self.assertEqual(refused(rows), every_one_of(rows, True))


class TestTheCollectorReadsAFunctionsOwnNameFromTheSamePlace(TestBase):

    def test_it_reports_on_every_expression_named_by_a_word_its_own_kind_reserves(self):
        rows = A_FUNCTION_EXPRESSION_NAMED_BY_A_WORD_ITS_OWN_KIND_RESERVES
        self.assertEqual(reported(rows, strict=False), every_one_of(rows, True))

    def test_it_reports_on_them_under_a_strict_seed_too(self):
        rows = A_FUNCTION_EXPRESSION_NAMED_BY_A_WORD_ITS_OWN_KIND_RESERVES
        self.assertEqual(reported(rows, strict=True), every_one_of(rows, True))

    def test_it_reports_on_no_expression_whose_own_kind_reserves_neither_word(self):
        rows = A_FUNCTION_EXPRESSION_NAME_ITS_OWN_KIND_LEAVES_ALONE
        self.assertEqual(reported(rows, strict=False), every_one_of(rows, False))

    def test_it_reports_on_no_declaration_the_enclosing_context_leaves_alone(self):
        rows = A_DECLARATION_WHOSE_NAME_THE_ENCLOSING_CONTEXT_GOVERNS
        self.assertEqual(reported(rows, strict=False), every_one_of(rows, False))


A_KIND_OF_FUNCTION = ('function', 'function*', 'async function', 'async function*')

A_CALL_THAT_RUNS_THE_BODY_OF = {
    'function'        : 'outer();',
    'function*'       : 'outer().next();',
    'async function'  : 'outer();',
    'async function*' : 'outer().next();',
}

A_FUNCTION_EXPRESSION_OF_KIND_NAMED: dict[str, dict[str, str | None]] = {
    'function'        : {'yield': 'yield\n', 'await': 'await\n'},
    'function*'       : {'yield': None, 'await': 'await\n'},
    'async function'  : {'yield': 'yield\n', 'await': None},
    'async function*' : {'yield': None, 'await': None},
}

#: The name is read from a plain function beside the declaration, so that the reference itself is
#: never what Node refuses.
A_FUNCTION_DECLARATION_INSIDE_KIND_NAMED: dict[str, dict[str, str | None]] = {
    'function'        : {'yield': 'yield\n', 'await': 'await\n'},
    'function*'       : {'yield': None, 'await': 'await\n'},
    'async function'  : {'yield': 'yield\n', 'await': None},
    'async function*' : {'yield': None, 'await': None},
}


def _an_expression_named(enclosing: str, kind: str, name: str) -> str:
    return (
        F'{enclosing} outer() {{ var f = {kind} {name}() {{}}; console.log(f.name); }}'
        F' {A_CALL_THAT_RUNS_THE_BODY_OF[enclosing]}'
    )


def _a_declaration_named(enclosing: str, kind: str, name: str) -> str:
    return (
        F'{enclosing} outer() {{ {kind} {name}() {{}}'
        F' (function () {{ console.log({name}.name); }})(); }}'
        F' {A_CALL_THAT_RUNS_THE_BODY_OF[enclosing]}'
    )


A_NAMED_FUNCTION_EXPRESSION_UNDER_EVERY_ENCLOSING_KIND: dict[str, str | None] = {
    _an_expression_named(enclosing, kind, name): printed
    for enclosing in A_CALL_THAT_RUNS_THE_BODY_OF
    for kind, answers in A_FUNCTION_EXPRESSION_OF_KIND_NAMED.items()
    for name, printed in answers.items()
}

A_NAMED_FUNCTION_DECLARATION_OF_EVERY_KIND: dict[str, str | None] = {
    _a_declaration_named(enclosing, kind, name): printed
    for enclosing, answers in A_FUNCTION_DECLARATION_INSIDE_KIND_NAMED.items()
    for kind in A_KIND_OF_FUNCTION
    for name, printed in answers.items()
}


def _the_pair_recorded_by(rows: dict[str, str | None]) -> dict[str, tuple[str, str | None]]:
    return {
        source: ('', 'SyntaxError') if printed is None else (printed, None)
        for source, printed in rows.items()
    }


def _spoken_by_node(programs: Iterable[str]) -> dict[str, tuple[str, str | None]]:
    return {program: behavior(program) for program in programs}


def _printed_and_parsed_again(source: str) -> str:
    return JsSynthesizer().convert(JsParser(source).parse())


def _spoken_after_a_round_trip(programs: Iterable[str]) -> dict[str, tuple[str, str | None]]:
    return {program: behavior(_printed_and_parsed_again(program)) for program in programs}


def _refused_as_a_strict_file(programs: Iterable[str]) -> dict[str, bool]:
    return {
        program: behavior(_under_a_strict_seed(program))[1] == 'SyntaxError'
        for program in programs
    }


def _node_refuses(rows: dict[str, str | None]) -> dict[str, bool]:
    return {source: printed is None for source, printed in rows.items()}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFunctionNamedYieldOrAwaitKeepsItsName(TestBase):

    def test_node_answers_each_named_expression_the_way_the_row_records(self):
        rows = A_NAMED_FUNCTION_EXPRESSION_UNDER_EVERY_ENCLOSING_KIND
        self.assertEqual(_spoken_by_node(rows), _the_pair_recorded_by(rows))

    def test_a_round_trip_answers_each_named_expression_the_same_way(self):
        rows = A_NAMED_FUNCTION_EXPRESSION_UNDER_EVERY_ENCLOSING_KIND
        self.assertEqual(_spoken_after_a_round_trip(rows), _the_pair_recorded_by(rows))

    def test_node_answers_each_named_declaration_the_way_the_row_records(self):
        rows = A_NAMED_FUNCTION_DECLARATION_OF_EVERY_KIND
        self.assertEqual(_spoken_by_node(rows), _the_pair_recorded_by(rows))

    def test_a_round_trip_answers_each_named_declaration_the_same_way(self):
        rows = A_NAMED_FUNCTION_DECLARATION_OF_EVERY_KIND
        self.assertEqual(_spoken_after_a_round_trip(rows), _the_pair_recorded_by(rows))

    def test_printing_a_named_expression_a_second_time_writes_the_same_text(self):
        rows = A_NAMED_FUNCTION_EXPRESSION_UNDER_EVERY_ENCLOSING_KIND
        once = {source: _printed_and_parsed_again(source) for source in rows}
        self.assertEqual(
            {source: _printed_and_parsed_again(text) for source, text in once.items()},
            once,
        )

    def test_printing_a_named_declaration_a_second_time_writes_the_same_text(self):
        rows = A_NAMED_FUNCTION_DECLARATION_OF_EVERY_KIND
        once = {source: _printed_and_parsed_again(source) for source in rows}
        self.assertEqual(
            {source: _printed_and_parsed_again(text) for source, text in once.items()},
            once,
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestTheCollectorRefusesAReservedFunctionNameWhereNodeDoes(TestBase):

    def test_it_reports_on_exactly_the_named_expressions_node_refuses(self):
        rows = A_NAMED_FUNCTION_EXPRESSION_UNDER_EVERY_ENCLOSING_KIND
        self.assertEqual(reported(rows, strict=False), _node_refuses(rows))

    def test_it_reports_on_exactly_the_named_declarations_node_refuses(self):
        rows = A_NAMED_FUNCTION_DECLARATION_OF_EVERY_KIND
        self.assertEqual(reported(rows, strict=False), _node_refuses(rows))

    def test_it_reports_on_exactly_the_named_expressions_a_strict_file_refuses(self):
        rows = A_NAMED_FUNCTION_EXPRESSION_UNDER_EVERY_ENCLOSING_KIND
        self.assertEqual(reported(rows, strict=True), _refused_as_a_strict_file(rows))

    def test_it_reports_on_exactly_the_named_declarations_a_strict_file_refuses(self):
        rows = A_NAMED_FUNCTION_DECLARATION_OF_EVERY_KIND
        self.assertEqual(reported(rows, strict=True), _refused_as_a_strict_file(rows))


class TestTheVerdictRefusesAFunctionNameWhereNodeDoes(TestBase):

    def test_a_name_the_kind_of_function_reserves_is_no_program(self):
        rows = [
            *A_NAME_THE_KIND_OF_FUNCTION_RESERVES,
            *A_NAME_THE_PARSER_REFUSES_TO_READ,
            *A_BINDING_THE_KIND_OF_FUNCTION_RESERVES,
            *A_FUNCTION_EXPRESSION_NAMED_BY_A_WORD_ITS_OWN_KIND_RESERVES,
            *A_CLASS_EXPRESSION_NAME_THE_ENCLOSING_KIND_RESERVES,
        ]
        self.assertEqual(each_well_formed(rows), every_one_of(rows, False))

    def test_a_name_only_some_other_kind_reserves_is_a_program(self):
        rows = [
            *A_FUNCTION_EXPRESSION_NAME_ITS_OWN_KIND_LEAVES_ALONE,
            *A_FUNCTION_EXPRESSION_NAME_ONLY_THE_ENCLOSING_KIND_RESERVES,
        ]
        self.assertEqual(each_well_formed(rows), every_one_of(rows, True))

    def test_the_same_declaration_inside_a_plain_function_is_a_program_where_node_reads_it(self):
        rows = THE_SAME_BINDING_INSIDE_A_PLAIN_FUNCTION
        self.assertEqual(
            each_well_formed(rows),
            {source: not refused for source, refused in rows.items()},
        )
