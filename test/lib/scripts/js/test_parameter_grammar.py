"""
What the language refuses about a function's signature, and whether the tool refuses the same texts.

Three of the early errors `refinery.lib.scripts.js.strict.collect_strict_violations` reports are
about a signature: a Use Strict Directive standing under a parameter list that is not simple, a name
repeated among the parameters, and the arity of an accessor. Only the second of the three asks what
mode the code runs in; the other two are refused whatever mode it is read under.

Which of them applies is decided by the position a function stands in rather than by the function:
`function (a, a) {}` is a program as the value of a property and a Syntax Error as a method, and the
two are the same node. `refinery.lib.scripts.js.strict.parameter_grammar` names that decision, and
whether it names it right is a question Node answers, the grammars differing in what they permit.

Node decides every expectation here, and the question put to it is whether it reads a text at all: a
program it refuses has no behaviour left to compare, and a text the collector reports on had better
be one of those. The correspondence is the law and it holds in both directions — reporting nothing
about a text Node refuses lets a deobfuscation hand back a file that no longer parses, and reporting
something about a text Node reads makes the tool decline work it could have done.

The seed is the mode a destination runs in and not anything the snippet says, so the file that
witnesses `strict=True` is the same snippet written below a `'use strict'` of its own.

SECURITY: every snippet here is hand-authored and benign, and running it is what makes the engine
the oracle. Nothing from `samples` may ever be fed to this.
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
from test.lib.scripts.js.test_directive_prologue import (
    A_FUNCTION_WRITTEN_AS,
    A_PARAMETER_LIST,
    NOT_A_PROGRAM,
)

from refinery.lib.scripts import is_well_formed
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
    """
    A place a function can be written, as the template writing one there, the `ParameterGrammar`
    its parameter list is then read through, and whether Node refuses a name repeated among those
    parameters when the file around it is sloppy.
    """
    template: str
    grammar: ParameterGrammar
    refuses_a_repeated_name: bool


#: A position a function stands in that takes a whole parameter list, so that a name may repeat
#: among the parameters at all. A repeated name is refused wherever the grammar is
#: `ParameterGrammar.UNIQUE`, and the two class fields are refused for a second reason: every part
#: of a class definition is strict code, and strict code refuses a repeated name under
#: `ParameterGrammar.FORMAL` as well.
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

#: A position a getter stands in. Every one of them takes no parameters at all.
A_GETTER_STANDING_AS = {
    'an object getter'         : 'var o = {{ get g({params}) {{ {body} }} }};',
    'a computed object getter' : "var o = {{ get ['g']({params}) {{ {body} }} }};",
    'a class getter'           : 'class C {{ get g({params}) {{ {body} }} }}',
    'a static class getter'    : 'class C {{ static get g({params}) {{ {body} }} }}',
    'a private class getter'   : 'class C {{ get #g({params}) {{ {body} }} }}',
}

#: A position a setter stands in. Every one of them takes exactly one parameter.
A_SETTER_STANDING_AS = {
    'an object setter'         : 'var o = {{ set s({params}) {{ {body} }} }};',
    'a computed object setter' : "var o = {{ set ['s']({params}) {{ {body} }} }};",
    'a class setter'           : 'class C {{ set s({params}) {{ {body} }} }}',
    'a static class setter'    : 'class C {{ static set s({params}) {{ {body} }} }}',
    'a private class setter'   : 'class C {{ set #s({params}) {{ {body} }} }}',
}

#: The parameter list each position is written with when the question is which grammar reads it.
#: A getter that takes one and a setter that takes none are Syntax Errors, so the three groups are
#: asked with a list the position permits.
A_LIST_THE_POSITION_PERMITS = 'a'
A_LIST_A_GETTER_PERMITS = ''
A_LIST_A_SETTER_PERMITS = 'v'

#: A parameter list holding one name twice, mapped to whether `FormalParameters` refuses it in
#: sloppy code. It does so once the list holds anything that is not a plain identifier, and the
#: repetition need not be inside that thing: a default value, a rest element or a pattern anywhere
#: in the list is enough.
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

#: A parameter list, mapped to whether a getter may be written with it.
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

#: The same lists, mapped to whether a setter may be written with them. A setter takes one
#: parameter and it may be anything a parameter can be, so the two accessors disagree about every
#: list but the rest element, which is refused for being one, and the two the count refuses.
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

#: A function body, mapped to whether it declares the Use Strict Directive. The directive is a
#: string literal standing plainly in the run of string-literal statements the body opens with, and
#: nothing else is one: a bracket around it, a template holding the same characters, an escape
#: spelling one of them, and a statement above it that is no string literal each leave a body that
#: declares nothing.
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

#: A parameter list that is not simple, and one that is. The directive rule is stated over the pair:
#: the same body is refused under the first and read under the second.
A_LIST_THAT_IS_NOT_SIMPLE = 'a = 1'
A_LIST_THAT_IS_SIMPLE = 'a'

#: An accessor holding the Use Strict Directive, mapped to whether Node refuses the file. A getter
#: takes no parameters and its list is therefore always simple; a setter takes one, which may be a
#: default or a pattern, and those are the accessors a directive may not stand under.
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

#: An arrow whose parameter list is not simple and whose body is an expression rather than a
#: statement list. No Directive Prologue is read in one at all, so the text that would be the
#: directive is the value the arrow answers with and Node reads every one of these.
AN_ARROW_WHOSE_BODY_IS_AN_EXPRESSION = [
    "var f = (a = 1) => 'use strict';",
    "var f = (a = 1) => ('use strict');",
    "var f = ([a]) => 'use strict';",
    "var f = (...a) => 'use strict';",
]

#: A function written into the parameter list of another, mapped to whether Node refuses the file.
#: Each rule is asked of the one signature it is about: the inner function's own list is simple and
#: the repeat in it is legal, however the list it stands inside is written, and it stops being legal
#: once a directive makes the inner function's own code strict. The outer list is not simple in any
#: of these, so the outer body may hold no directive whatever stands in the inner one.
A_FUNCTION_WRITTEN_INTO_ANOTHERS_PARAMETER_LIST = {
    'function f(a = function (b, b) {}) {}'                : False,
    'function f(a = function (b) {}) {}'                   : False,
    "function f(a = function (b, b) { 'use strict'; }) {}" : True,
    "function f(a = function (b, b) {}) { 'use strict'; }" : True,
    "function f(a = function (b) {}) { 'use strict'; }"    : True,
}

#: A file holding a repeated parameter name somewhere in it, mapped to whether Node refuses to read
#: it. Nothing in any of these is seeded as strict, so what parts them is where the strictness comes
#: from: a directive the function's own body declares reaches the parameter list above it, a
#: directive in a body nested inside it reaches nothing, a class makes everything it holds strict,
#: and a text that only looks like a directive declares no mode at all.
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

#: A name reserved by the kind of function it is written in rather than by the mode the file runs
#: in: a generator reserves `yield` and an async function reserves `await`, in every position and
#: whether or not anything around them declares a mode. Node refuses every one of these files as a
#: sloppy one and as a strict one alike.
A_NAME_THE_KIND_OF_FUNCTION_RESERVES = [
    'function* g(yield) {}',
    'function* g(a = yield) {}',
    'function* g() { var yield = 1; }',
    'var o = { *m(yield) {} };',
    'async function h(await) {}',
    'async function h(a = await) {}',
    'var f = async (await) => {};',
    'var o = { async m(await) {} };',
]

#: The same reservation asked of a declaration's name rather than of a parameter or a reference.
#: Node refuses every one of these too.
A_BINDING_THE_KIND_OF_FUNCTION_RESERVES = [
    'function* g() { function yield() {} }',
    'function* g() { class yield {} }',
    'async function h() { function await() {} }',
    'async function h() { class await {} }',
]

#: The same four declarations written inside a plain function, mapped to whether Node refuses the
#: file. Three of them are programs, so it is the kind of the enclosing function and nothing else
#: that costs the first group its reading. The fourth is refused for a reason of its own: a class
#: name is strict code wherever the class stands, and `yield` is a strict-mode reserved word.
THE_SAME_BINDING_INSIDE_A_PLAIN_FUNCTION = {
    'function g() { function yield() {} }' : False,
    'function g() { class yield {} }'      : True,
    'function h() { function await() {} }' : False,
    'function h() { class await {} }'      : False,
}

#: A function expression named by the word its own kind reserves. An expression's name is bound
#: inside the function and is read under the function's own kind, so the reservation reaches it
#: however sloppy the file is and whatever encloses it. Node refuses every one of these.
A_FUNCTION_EXPRESSION_NAMED_BY_A_WORD_ITS_OWN_KIND_RESERVES = [
    'var x = function* yield() {};',
    'var x = (function* yield() {});',
    'var x = async function await() {};',
    'var o = { m: function* yield() {} };',
    'var o = { m: async function await() {} };',
    'function p() { var f = function* yield() {}; }',
    'function p() { var f = async function await() {}; }',
]

#: The same words naming a function expression of a kind that reserves neither of them, and the
#: word the other kind reserves. Node reads every one of these files.
A_FUNCTION_EXPRESSION_NAME_ITS_OWN_KIND_LEAVES_ALONE = [
    'var x = function yield() {};',
    'var x = function await() {};',
    'var x = async function yield() {};',
    'var x = function* await() {};',
]

#: The same words naming a declaration rather than an expression. A declaration's name is bound
#: outside the function and is read under whatever encloses it, so a declaration of either kind is a
#: program wherever nothing around it reserves the word. Node reads every one of these files.
A_DECLARATION_WHOSE_NAME_THE_ENCLOSING_CONTEXT_GOVERNS = [
    'function* yield() {}',
    'async function await() {}',
    'function p() { function* yield() {} }',
    'function p() { async function await() {} }',
]

#: A function expression of a kind that reserves neither word, named by the word the kind of the
#: function around it reserves. The name is read under the expression's own kind, so a reservation
#: the surroundings carry does not reach it and Node reads every one of these files. A directive is
#: no defence for the `await` half, which no strict body reserves. What the tool makes of them is
#: pinned in `test.lib.scripts.js.test_unfixed_defects`.
A_FUNCTION_EXPRESSION_NAME_ONLY_THE_ENCLOSING_KIND_RESERVES = [
    'function* g() { var f = function yield() { return 1; }; }',
    'async function h() { var f = function await() { return 1; }; }',
    'var o = { *m() { var f = function yield() { return 1; }; } };',
    'var o = { async m() { var f = function await() { return 1; }; } };',
    'function* g() { (function yield() { return 1; })(); }',
    "'use strict'; async function h() { var f = function await() { return 1; }; }",
]

#: A class expression standing in the same places, named by the same words. A class name is read
#: under the context the class stands in rather than under a kind of the class's own, so the
#: reservation does reach it and Node refuses every one of these files.
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
    """
    *source* written below a Use Strict Directive of its own, which is the file that witnesses what
    the seed `strict=True` stands for: the mode of the destination a payload is about to be read in.
    """
    return F"'use strict';\n{source}"


def _refused(programs: Sequence[str]) -> dict[str, bool]:
    """
    Whether Node refuses to read each of *programs* as a program at all. Each is compiled and run in
    a context of its own, so a refusal is a fact about that one text.
    """
    return {
        program: value == NOT_A_PROGRAM
        for program, value in zip(programs, completion_values(programs, JsEvaluation.SCRIPT))
    }


def _reported(programs: Iterable[str], *, strict: bool) -> dict[str, bool]:
    """
    Whether `refinery.lib.scripts.js.strict.collect_strict_violations` reports anything at all about
    each of *programs* under the seeded mode.
    """
    return {
        program: bool(collect_strict_violations(JsParser(program).parse(), strict=strict))
        for program in programs
    }


def _refused_under_a_strict_seed(programs: Iterable[str]) -> dict[str, bool]:
    return _refused([_under_a_strict_seed(program) for program in programs])


def _every_one_of(programs: Iterable[str], answer: bool) -> dict[str, bool]:
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
        self.assertEqual(_refused(list(rows)), rows)

    def test_a_strict_file_refuses_a_repeated_name_in_every_position(self):
        rows = _a_repeated_name_in_every_position()
        strict = [_under_a_strict_seed(program) for program in rows]
        self.assertEqual(_refused(strict), _every_one_of(strict, True))

    def test_node_reads_every_one_of_those_positions_with_no_name_repeated(self):
        rows = [
            position.template.format(params=params, body='')
            for position in A_FUNCTION_STANDING_AS.values()
            for params in A_PARAMETER_LIST
        ]
        self.assertEqual(_refused(rows), _every_one_of(rows, False))


class TestTheCollectorReportsARepeatedParameterNameWhereNodeDoes(TestBase):

    def test_it_reports_on_exactly_the_positions_a_sloppy_file_refuses(self):
        rows = _a_repeated_name_in_every_position()
        self.assertEqual(_reported(rows, strict=False), rows)

    def test_it_reports_on_every_position_under_a_strict_seed(self):
        rows = _a_repeated_name_in_every_position()
        self.assertEqual(_reported(rows, strict=True), _every_one_of(rows, True))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestWhichParameterListsAnAccessorMayBeWrittenWith(TestBase):

    def test_node_refuses_each_getter_the_corpus_records(self):
        rows = _every_list_in(A_GETTER_STANDING_AS.values(), A_LIST_A_GETTER_MAY_TAKE)
        self.assertEqual(_refused(list(rows)), rows)

    def test_node_refuses_each_setter_the_corpus_records(self):
        rows = _every_list_in(A_SETTER_STANDING_AS.values(), A_LIST_A_SETTER_MAY_TAKE)
        self.assertEqual(_refused(list(rows)), rows)

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
        self.assertEqual(_reported(rows, strict=False), rows)

    def test_it_reports_on_exactly_the_setters_node_refuses(self):
        rows = _every_list_in(A_SETTER_STANDING_AS.values(), A_LIST_A_SETTER_MAY_TAKE)
        self.assertEqual(_reported(rows, strict=False), rows)

    def test_the_seeded_mode_moves_no_accessor(self):
        rows = {
            **_every_list_in(A_GETTER_STANDING_AS.values(), A_LIST_A_GETTER_MAY_TAKE),
            **_every_list_in(A_SETTER_STANDING_AS.values(), A_LIST_A_SETTER_MAY_TAKE),
        }
        self.assertEqual(_reported(rows, strict=True), rows)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestWhereADirectiveMayStandUnderAParameterList(TestBase):

    def test_node_refuses_a_body_that_declares_one_under_a_list_that_is_not_simple(self):
        rows = _every_body_under(A_LIST_THAT_IS_NOT_SIMPLE)
        self.assertEqual(_refused(list(rows)), rows)

    def test_node_reads_every_one_of_those_bodies_under_a_list_that_is_simple(self):
        rows = _every_body_under(A_LIST_THAT_IS_SIMPLE)
        self.assertEqual(_refused(list(rows)), _every_one_of(rows, False))

    def test_a_strict_file_refuses_the_same_bodies(self):
        rows = _every_body_under(A_LIST_THAT_IS_NOT_SIMPLE)
        self.assertEqual(
            _refused_under_a_strict_seed(rows),
            {_under_a_strict_seed(program): declares for program, declares in rows.items()},
        )

    def test_node_decides_each_accessor_the_corpus_records(self):
        rows = AN_ACCESSOR_HOLDING_THE_DIRECTIVE
        self.assertEqual(_refused(list(rows)), dict(rows))

    def test_node_reads_an_arrow_whose_body_is_an_expression(self):
        rows = AN_ARROW_WHOSE_BODY_IS_AN_EXPRESSION
        self.assertEqual(_refused(rows), _every_one_of(rows, False))

    def test_node_decides_each_nested_function_the_corpus_records(self):
        rows = A_FUNCTION_WRITTEN_INTO_ANOTHERS_PARAMETER_LIST
        self.assertEqual(_refused(list(rows)), dict(rows))


class TestTheCollectorReportsADirectiveWhereNodeRefusesOne(TestBase):

    def test_it_reports_on_exactly_the_bodies_that_declare_one(self):
        rows = _every_body_under(A_LIST_THAT_IS_NOT_SIMPLE)
        self.assertEqual(_reported(rows, strict=False), rows)

    def test_it_reports_on_none_of_them_under_a_list_that_is_simple(self):
        rows = _every_body_under(A_LIST_THAT_IS_SIMPLE)
        self.assertEqual(_reported(rows, strict=False), _every_one_of(rows, False))

    def test_the_seeded_mode_moves_no_body(self):
        rows = _every_body_under(A_LIST_THAT_IS_NOT_SIMPLE)
        self.assertEqual(_reported(rows, strict=True), rows)

    def test_it_reports_on_exactly_the_accessors_node_refuses(self):
        rows = AN_ACCESSOR_HOLDING_THE_DIRECTIVE
        self.assertEqual(_reported(rows, strict=False), dict(rows))

    def test_it_reports_on_no_arrow_whose_body_is_an_expression(self):
        rows = AN_ARROW_WHOSE_BODY_IS_AN_EXPRESSION
        self.assertEqual(_reported(rows, strict=False), _every_one_of(rows, False))

    def test_it_reports_on_exactly_the_nested_functions_node_refuses(self):
        rows = A_FUNCTION_WRITTEN_INTO_ANOTHERS_PARAMETER_LIST
        self.assertEqual(_reported(rows, strict=False), dict(rows))


class TestWhichShapesADirectiveIsPermittedUnderAreTheSameOnesTheCollectorReads(TestBase):
    """
    Which parameter lists permit a Use Strict Directive under them is law in
    `test.lib.scripts.js.test_directive_prologue`, over the same two corpora this crosses: Node
    refuses a directive under every list that is not simple, in every shape a function is written
    in, and reads every one of those lists with an empty body.
    """

    def test_the_collector_reports_on_a_directive_under_every_list_that_is_not_simple(self):
        for shape, template in A_FUNCTION_WRITTEN_AS.items():
            rows = {
                template.format(params=params, body="'use strict';"): not simple
                for params, simple in A_PARAMETER_LIST.items()
            }
            with self.subTest(shape=shape):
                self.assertEqual(_reported(rows, strict=False), rows)

    def test_the_collector_reports_on_none_of_those_lists_with_an_empty_body(self):
        for shape, template in A_FUNCTION_WRITTEN_AS.items():
            rows = [template.format(params=params, body='') for params in A_PARAMETER_LIST]
            with self.subTest(shape=shape):
                self.assertEqual(_reported(rows, strict=False), _every_one_of(rows, False))


class TestWhichGrammarAFunctionTakesItsParametersThrough(TestBase):
    """
    The grammar recorded for each position is what the refusals above are stated over: a position
    recorded `ParameterGrammar.UNIQUE` is one Node refuses a repeated name in, a `GETTER` takes no
    parameters and a `SETTER` takes exactly one, and `ParameterGrammar.FORMAL` is what is left.
    """

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
        self.assertEqual(_refused(list(rows)), dict(rows))


class TestTheCollectorReadsTheStrictnessFromTheSamePlace(TestBase):

    def test_it_reports_on_exactly_the_files_node_refuses(self):
        rows = A_REPEATED_NAME_MADE_AN_ERROR_BY
        self.assertEqual(_reported(rows, strict=False), dict(rows))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestANameTheKindOfFunctionReserves(TestBase):

    def test_node_refuses_every_one_of_them_as_a_sloppy_file(self):
        rows = A_NAME_THE_KIND_OF_FUNCTION_RESERVES
        self.assertEqual(_refused(rows), _every_one_of(rows, True))

    def test_node_refuses_every_one_of_them_as_a_strict_file(self):
        rows = A_NAME_THE_KIND_OF_FUNCTION_RESERVES
        self.assertEqual(
            _refused_under_a_strict_seed(rows),
            _every_one_of([_under_a_strict_seed(program) for program in rows], True),
        )

    def test_node_refuses_the_same_word_used_to_name_a_declaration(self):
        rows = A_BINDING_THE_KIND_OF_FUNCTION_RESERVES
        self.assertEqual(_refused(rows), _every_one_of(rows, True))

    def test_node_reads_those_declarations_inside_a_function_of_no_reserving_kind(self):
        rows = THE_SAME_BINDING_INSIDE_A_PLAIN_FUNCTION
        self.assertEqual(_refused(list(rows)), dict(rows))


class TestTheCollectorReportsANameTheKindOfFunctionReserves(TestBase):
    """
    The reservation belongs to the kind of function and not to the mode, so the collector has to
    report on the same files under either seed. That is what makes it usable as a gate on a payload
    whose destination is not yet known.
    """

    def test_it_reports_on_every_name_node_refuses_under_a_sloppy_seed(self):
        rows = A_NAME_THE_KIND_OF_FUNCTION_RESERVES
        self.assertEqual(_reported(rows, strict=False), _every_one_of(rows, True))

    def test_it_reports_on_every_one_of_them_under_a_strict_seed(self):
        rows = A_NAME_THE_KIND_OF_FUNCTION_RESERVES
        self.assertEqual(_reported(rows, strict=True), _every_one_of(rows, True))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestWhichContextGovernsAFunctionsOwnName(TestBase):
    """
    A function's name is governed by one context and never by two, and which one it is depends on
    how the function is written. An expression's name is bound inside it and is read under its own
    kind, so a generator expression may not be named `yield` even where nothing around it is a
    generator. A declaration's name is bound outside it and is read under whatever encloses it, so a
    generator declaration named `yield` is a program wherever the enclosing code reserves nothing.
    """

    def test_node_refuses_every_expression_named_by_a_word_its_own_kind_reserves(self):
        rows = A_FUNCTION_EXPRESSION_NAMED_BY_A_WORD_ITS_OWN_KIND_RESERVES
        self.assertEqual(_refused(rows), _every_one_of(rows, True))

    def test_node_refuses_them_under_a_strict_seed_too(self):
        rows = A_FUNCTION_EXPRESSION_NAMED_BY_A_WORD_ITS_OWN_KIND_RESERVES
        self.assertEqual(
            _refused_under_a_strict_seed(rows),
            _every_one_of([_under_a_strict_seed(program) for program in rows], True),
        )

    def test_node_reads_an_expression_whose_own_kind_reserves_neither_word(self):
        rows = A_FUNCTION_EXPRESSION_NAME_ITS_OWN_KIND_LEAVES_ALONE
        self.assertEqual(_refused(rows), _every_one_of(rows, False))

    def test_node_reads_the_same_word_naming_a_declaration(self):
        rows = A_DECLARATION_WHOSE_NAME_THE_ENCLOSING_CONTEXT_GOVERNS
        self.assertEqual(_refused(rows), _every_one_of(rows, False))

    def test_node_reads_an_expression_only_the_kind_around_it_reserves_the_name_of(self):
        rows = A_FUNCTION_EXPRESSION_NAME_ONLY_THE_ENCLOSING_KIND_RESERVES
        self.assertEqual(_refused(rows), _every_one_of(rows, False))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestWhichContextGovernsAClassExpressionsOwnName(TestBase):
    """
    A class expression's name is not read the way a function expression's is. It is read under the
    context the class stands in, so the word the kind of the function around it reserves reaches the
    name, and the file is refused where the same name on a function expression is a program.
    """

    def test_node_refuses_every_class_expression_the_kind_around_it_reserves_the_name_of(self):
        rows = A_CLASS_EXPRESSION_NAME_THE_ENCLOSING_KIND_RESERVES
        self.assertEqual(_refused(rows), _every_one_of(rows, True))


class TestTheCollectorReadsAFunctionsOwnNameFromTheSamePlace(TestBase):

    def test_it_reports_on_every_expression_named_by_a_word_its_own_kind_reserves(self):
        rows = A_FUNCTION_EXPRESSION_NAMED_BY_A_WORD_ITS_OWN_KIND_RESERVES
        self.assertEqual(_reported(rows, strict=False), _every_one_of(rows, True))

    def test_it_reports_on_them_under_a_strict_seed_too(self):
        rows = A_FUNCTION_EXPRESSION_NAMED_BY_A_WORD_ITS_OWN_KIND_RESERVES
        self.assertEqual(_reported(rows, strict=True), _every_one_of(rows, True))

    def test_it_reports_on_no_expression_whose_own_kind_reserves_neither_word(self):
        rows = A_FUNCTION_EXPRESSION_NAME_ITS_OWN_KIND_LEAVES_ALONE
        self.assertEqual(_reported(rows, strict=False), _every_one_of(rows, False))

    def test_it_reports_on_no_declaration_the_enclosing_context_leaves_alone(self):
        rows = A_DECLARATION_WHOSE_NAME_THE_ENCLOSING_CONTEXT_GOVERNS
        self.assertEqual(_reported(rows, strict=False), _every_one_of(rows, False))


#: The four kinds of function, spelled the way the source writes one.
A_KIND_OF_FUNCTION = ('function', 'function*', 'async function', 'async function*')

#: The call that runs the body of a function of each kind. A generator and an async generator hand
#: back an iterator and run nothing until it is stepped, so a program that only calls one prints
#: nothing at all and would report the same for a name kept and a name lost.
A_CALL_THAT_RUNS_THE_BODY_OF = {
    'function'        : 'outer();',
    'function*'       : 'outer().next();',
    'async function'  : 'outer();',
    'async function*' : 'outer().next();',
}

#: A kind of function expression and the word naming it, mapped to what Node prints for a program
#: that reports the expression's own `name`, or to `None` where Node reads no program at all. An
#: expression's name is bound inside the function and read under the expression's own kind: a
#: generator reserves `yield`, an async function reserves `await`, and an async generator reserves
#: both. Each row stands for the four programs writing that expression inside a function of each
#: kind, because the kind of the function around it decides nothing about the name.
A_FUNCTION_EXPRESSION_OF_KIND_NAMED: dict[str, dict[str, str | None]] = {
    'function'        : {'yield': 'yield\n', 'await': 'await\n'},
    'function*'       : {'yield': None, 'await': 'await\n'},
    'async function'  : {'yield': 'yield\n', 'await': None},
    'async function*' : {'yield': None, 'await': None},
}

#: The kind of function a declaration stands inside and the word naming that declaration, mapped to
#: what Node prints for a program that reports the declaration's `name`, or to `None` where Node
#: reads no program at all. A declaration's name is bound outside the function and read under
#: whatever encloses it, so the table is the same one and it is read the other way round: each row
#: stands for the four programs writing that declaration with a kind of its own, because the kind of
#: the declaration decides nothing about its name. The name is read from a plain function beside the
#: declaration, where neither word is reserved, so that the reference is never the reason for a
#: refusal.
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
    """
    A named function expression carries its name into the program: the name is bound inside the
    function and is what `Function.prototype.name` answers with, so a rewrite that drops it changes
    what the program prints. `yield` and `await` are the two names a kind of function can reserve,
    and the reservation is what makes half of these texts programs and the other half not, which
    puts the printer and the early-error collector on the same corpus.
    """

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
    """
    The collector is the gate that keeps a payload out of a destination that would refuse it, so the
    texts it reports on have to be the texts an engine refuses and no others. Under a sloppy seed
    that is Node's verdict on the file as written; under a strict seed it is Node's verdict on the
    same file below a Use Strict Directive, which is one more word Node reserves and the collector
    must therefore report one more group of texts under.
    """

    def test_it_reports_on_exactly_the_named_expressions_node_refuses(self):
        rows = A_NAMED_FUNCTION_EXPRESSION_UNDER_EVERY_ENCLOSING_KIND
        self.assertEqual(_reported(rows, strict=False), _node_refuses(rows))

    def test_it_reports_on_exactly_the_named_declarations_node_refuses(self):
        rows = A_NAMED_FUNCTION_DECLARATION_OF_EVERY_KIND
        self.assertEqual(_reported(rows, strict=False), _node_refuses(rows))

    def test_it_reports_on_exactly_the_named_expressions_a_strict_file_refuses(self):
        rows = A_NAMED_FUNCTION_EXPRESSION_UNDER_EVERY_ENCLOSING_KIND
        self.assertEqual(_reported(rows, strict=True), _refused_as_a_strict_file(rows))

    def test_it_reports_on_exactly_the_named_declarations_a_strict_file_refuses(self):
        rows = A_NAMED_FUNCTION_DECLARATION_OF_EVERY_KIND
        self.assertEqual(_reported(rows, strict=True), _refused_as_a_strict_file(rows))


class TestTheVerdictRefusesAFunctionNameWhereNodeDoes(TestBase):
    """
    `refinery.lib.scripts.is_well_formed` is the tool's answer to the question Node was asked of
    every file above, so the two agree on all of them: a declaration named by a word the kind of the
    enclosing function reserves is no program, and neither is an expression named by a word its own
    kind reserves, while the names only some other kind reserves are programs. The declarations of
    `A_BINDING_THE_KIND_OF_FUNCTION_RESERVES` used to come back well formed with the name read as
    absent, printed as `class {\\n    {;\\n  }`.
    """

    @staticmethod
    def _well_formed(programs: Iterable[str]) -> dict[str, bool]:
        return {program: is_well_formed(JsParser(program).parse()) for program in programs}

    def test_a_name_the_kind_of_function_reserves_is_no_program(self):
        rows = [
            *A_NAME_THE_KIND_OF_FUNCTION_RESERVES,
            *A_BINDING_THE_KIND_OF_FUNCTION_RESERVES,
            *A_FUNCTION_EXPRESSION_NAMED_BY_A_WORD_ITS_OWN_KIND_RESERVES,
            *A_CLASS_EXPRESSION_NAME_THE_ENCLOSING_KIND_RESERVES,
        ]
        self.assertEqual(self._well_formed(rows), _every_one_of(rows, False))

    def test_a_name_only_some_other_kind_reserves_is_a_program(self):
        rows = [
            *A_FUNCTION_EXPRESSION_NAME_ITS_OWN_KIND_LEAVES_ALONE,
            *A_FUNCTION_EXPRESSION_NAME_ONLY_THE_ENCLOSING_KIND_RESERVES,
        ]
        self.assertEqual(self._well_formed(rows), _every_one_of(rows, True))

    def test_the_same_declaration_inside_a_plain_function_is_a_program_where_node_reads_it(self):
        rows = THE_SAME_BINDING_INSIDE_A_PLAIN_FUNCTION
        self.assertEqual(
            self._well_formed(rows),
            {source: not refused for source, refused in rows.items()},
        )
