"""
A `'use strict'` is the Use Strict Directive only in the Directive Prologue: the run of statements
made of a string literal alone that a script, a function body or a class static block opens with. At
the head of any other statement list, such as a block, a `catch` clause, a loop body or a `case`, it
is an ordinary statement, and so is `('use strict');` anywhere.

Everything a strict body encloses is strict, and so is every part of a class. A function body's
directive also governs the name and the parameters of the function, and a function whose parameters
are not all plain identifiers may hold no directive at all, so Node refuses both of these:

    function eval() { 'use strict'; }
    function f(a = 1) { 'use strict'; }

The octal literal `010` most programs here hold is a SyntaxError in strict code and a number in
sloppy code, so whether Node refuses a program tells the mode of the position the literal stands in.
Node 22 runs a class field initializer, a static block, a heritage clause and a computed key strict
but reads an octal literal in each of them, so the programs that stand there hold `delete x`, which
every Node refuses in strict code and reads in sloppy code.

SECURITY: every snippet here is hand-authored and benign and is run by Node. Nothing from `samples`
may ever be fed to this.
"""
from __future__ import annotations

import inspect
import unittest

from typing import Sequence

from test import TestBase, opportunity
from test.lib.scripts.js.analysis.differential import (
    JsEvaluation,
    behavior,
    completion_values,
    deobfuscate_source,
    host_behavior,
    node_executable,
)
from test.lib.scripts.js.analysis.test_differential import (
    SPELLINGS_A_FOLD_WRITES_AS_A_PLAIN_STRING,
    SPELLINGS_A_FOLD_WRITES_AS_THE_DIRECTIVE,
    a_file_holding_an_octal_literal_opening_with,
    a_function_body_opening_with,
    a_script_opening_with,
    a_script_whose_directive_stands_below,
)

from refinery.lib.scripts import Node
from refinery.lib.scripts.js.model import (
    JsArrowFunctionExpression,
    JsCallExpression,
    JsExpressionStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsNumericLiteral,
    JsScript,
    JsStringLiteral,
    JsUnaryExpression,
    strip_parens,
)
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.strict import (
    declares_use_strict,
    directive_prologue,
    has_simple_parameters,
    is_prologue_host,
    is_use_strict_directive,
    joins_directive_prologue,
    strict_mode_at,
)
from refinery.units.scripting.djs import djs

NOT_A_PROGRAM = 'throw SyntaxError'

THE_DIRECTIVE = "'use strict'; "

A_BODY_A_PROLOGUE_OPENS = {
    'a script'               : "'use strict'; 010;",
    'a function declaration' : "function f() { 'use strict'; 010; }",
    'a function expression'  : "var f = function () { 'use strict'; 010; };",
    'an arrow with a block'  : "var f = () => { 'use strict'; 010; };",
    'a method'               : "var o = { m() { 'use strict'; 010; } };",
    'a getter'               : "var o = { get g() { 'use strict'; 010; } };",
    'a setter'               : "var o = { set s(v) { 'use strict'; 010; } };",
    'a generator'            : "function* g() { 'use strict'; 010; }",
    'an async function'      : "async function h() { 'use strict'; 010; }",
    'a nested function'      : "function f() { function g() { 'use strict'; 010; } }",
}

A_BODY_NO_PROLOGUE_OPENS = {
    'a plain block'          : "{ 'use strict'; 010; }",
    'an if branch'           : "if (1) { 'use strict'; 010; }",
    'an else branch'         : "if (0) ; else { 'use strict'; 010; }",
    'a try block'            : "try { 'use strict'; 010; } catch (e) {}",
    'a catch block'          : "try {} catch (e) { 'use strict'; 010; }",
    'a finally block'        : "try {} finally { 'use strict'; 010; }",
    'a for body'             : "for (;;) { 'use strict'; 010; break; }",
    'a for-in body'          : "for (var k in {}) { 'use strict'; 010; }",
    'a for-of body'          : "for (var v of []) { 'use strict'; 010; }",
    'a while body'           : "while (0) { 'use strict'; 010; }",
    'a do-while body'        : "do { 'use strict'; 010; } while (0);",
    'a switch case'          : "switch (1) { case 1: 'use strict'; 010; }",
    'a switch default'       : "switch (1) { default: 'use strict'; 010; }",
    'a labelled block'       : "L: { 'use strict'; 010; }",
    'a with block'           : "with ({}) { 'use strict'; 010; }",
    'a block inside a body'  : "function f() { { 'use strict'; 010; } }",
}

A_CLASS_STATIC_BLOCK = "class C { static { 'use strict'; delete x; } }"

A_STRICT_ERROR_STANDING_IN = {
    'a sloppy script'                    : ('010;', False),
    'a sloppy function body'             : ('function f() { 010; }', False),
    'a strict script'                    : ("'use strict'; 010;", True),
    'a function inside a strict script'  : ("'use strict'; function f() { 010; }", True),
    'an arrow inside a strict script'    : ("'use strict'; var f = () => 010;", True),
    'a block inside a strict script'     : ("'use strict'; { 010; }", True),
    'a function inside a strict body'    : (
        "function f() { 'use strict'; function g() { 010; } }", True),
    'a catch inside a strict body'       : (
        "function f() { 'use strict'; try {} catch (e) { 010; } }", True),
    'a class method'                     : ('class C { m() { 010; } }', True),
    'a class field initializer'          : ('class C { p = delete x; }', True),
    'a class static block'               : ('class C { static { delete x; } }', True),
    'a class heritage clause'            : ('class C extends (delete x, Object) {}', True),
    'a class computed key'               : ('class C { [delete x]() {} }', True),
    'a function inside a class method'   : ('class C { m() { function g() { 010; } } }', True),
    'a class expression method'          : ('var C = class { m() { 010; } };', True),
    'a script below a strict function'   : ("function f() { 'use strict'; } 010;", False),
    'a script below a block holding one' : ("{ 'use strict'; } 010;", False),
    'a body below a block holding one'   : ("function f() { { 'use strict'; } 010; }", False),
}

A_BINDING_THE_DIRECTIVE_GOVERNS = {
    'the name of a declaration'      : "function eval() { 'use strict'; }",
    'the name of an expression'      : "var f = function eval() { 'use strict'; };",
    'the name of a generator'        : "function* eval() { 'use strict'; }",
    'the name of an async function'  : "async function eval() { 'use strict'; }",
    'the name of a nested function'  : "function f() { function eval() { 'use strict'; } }",
    'the parameter of a declaration' : "function f(eval) { 'use strict'; }",
    'a later parameter'              : "function f(a, eval) { 'use strict'; }",
    'the parameter of an expression' : "var f = function (eval) { 'use strict'; };",
    'the parameter of a named one'   : "var f = function g(eval) { 'use strict'; };",
    'the parameter of an arrow'      : "var f = (eval) => { 'use strict'; };",
    'the parameter of a method'      : "var o = { m(eval) { 'use strict'; } };",
    'the parameter of a setter'      : "var o = { set s(eval) { 'use strict'; } };",
    'the parameter of a generator'   : "function* g(eval) { 'use strict'; }",
    'the parameter of an async one'  : "async function h(eval) { 'use strict'; }",
    'a binding inside the body'      : "function f() { 'use strict'; var eval = 1; }",
}

A_BINDING_OUTSIDE_WHAT_IT_GOVERNS = {
    'a binding above the function'       : "var eval = 1; function f() { 'use strict'; }",
    'a binding below the function'       : "function f() { 'use strict'; } var eval = 1;",
    'the name of a sibling function'     : "function eval() {} function f() { 'use strict'; }",
    'the key of a method'                : "var o = { eval() { 'use strict'; } };",
    'the key of a getter'                : "var o = { get eval() { 'use strict'; } };",
    'the variable an arrow is put in'    : "var eval = () => { 'use strict'; };",
    'the variable a function is put in'  : "var eval = function () { 'use strict'; };",
    'the name of the function around'    : "function eval() { function g() { 'use strict'; } }",
    'a parameter of the function around' : "function f(eval) { function g() { 'use strict'; } }",
}

A_STATEMENT_ABOVE_THE_DIRECTIVE = {
    ''                    : True,
    "'other';"            : True,
    '"another";'          : True,
    "'a'; 'b';"           : True,
    R"'use\u0020strict';" : True,
    ';'                   : False,
    '0;'                  : False,
    'var x;'              : False,
    "('paren');"          : False,
    "'a' + 'b';"          : False,
    "'a', 'b';"           : False,
    'x = 1;'              : False,
    "{ 'x'; }"            : False,
    "if (0) 'x';"         : False,
    'function g() {}'     : False,
    "'a'.length;"         : False,
}

A_BODY_WRITTEN_AS = ["'alpha';", "'beta';", '0;', "'gamma';"]

A_STATEMENT_STANDING_AT = {
    'the head of a script'           : ("{stmt} 'use strict'; 010;", True),
    'the second statement'           : ("'lead'; {stmt} 'use strict'; 010;", True),
    'below a statement that is none' : ("0; {stmt} 'use strict'; 010;", False),
    'the head of a function body'    : ("function f() {{ {stmt} 'use strict'; 010; }}", True),
    'the head of a plain block'      : ("{{ {stmt} 'use strict'; 010; }}", False),
    'the head of a switch case'      : (
        "switch (1) {{ case 1: {stmt} 'use strict'; 010; }}", False),
    'the head of a catch block'      : (
        "try {{}} catch (e) {{ {stmt} 'use strict'; 010; }}", False),
    'the head of a nested block'     : (
        "function f() {{ {{ {stmt} 'use strict'; 010; }} }}", False),
}

A_COMPUTED_STRING = "'a' + 'b';"

A_PLAIN_STRING = "'ab';"

A_PARAMETER_LIST = {
    ''          : True,
    'a'         : True,
    'a, b'      : True,
    'a, b, c'   : True,
    'a,'        : True,
    'a = 1'     : False,
    'a, b = 2'  : False,
    '...a'      : False,
    'a, ...b'   : False,
    '[a]'       : False,
    '[a, b]'    : False,
    '{a}'       : False,
    '{a: b}'    : False,
    '{a} = {}'  : False,
    'a, [b]'    : False,
}

A_FUNCTION_WRITTEN_AS = {
    'a function declaration' : 'function f({params}) {{ {body} }}',
    'a function expression'  : 'var f = function ({params}) {{ {body} }};',
    'an arrow'               : 'var f = ({params}) => {{ {body} }};',
    'a method'               : 'var o = {{ m({params}) {{ {body} }} }};',
    'a generator'            : 'function* g({params}) {{ {body} }}',
    'an async function'      : 'async function h({params}) {{ {body} }}',
}

_THE_MODE_IT_STANDS_IN = '(function () { return this; })() === undefined'

_REPORTS_THE_MODE_IT_STANDS_IN = F'console.log({_THE_MODE_IT_STANDS_IN});'

A_PROGRAM_REPORTING_ITS_MODE = {
    F"'use strict';\n{_REPORTS_THE_MODE_IT_STANDS_IN}":
        'true\n',
    F"'use strict';\nfunction f() {{ {_REPORTS_THE_MODE_IT_STANDS_IN} }}\nf();":
        'true\n',
    F"function f() {{ 'use strict'; {_REPORTS_THE_MODE_IT_STANDS_IN} }}\nf();":
        'true\n',
    F"var o = {{ m() {{ 'use strict'; {_REPORTS_THE_MODE_IT_STANDS_IN} }} }};\no.m();":
        'true\n',
    F"var f = () => {{ 'use strict'; {_REPORTS_THE_MODE_IT_STANDS_IN} }};\nf();":
        'true\n',
    F"function* g() {{ 'use strict'; {_REPORTS_THE_MODE_IT_STANDS_IN} }}\ng().next();":
        'true\n',
    F"var o = {{ get p() {{ 'use strict'; {_REPORTS_THE_MODE_IT_STANDS_IN} }} }};\no.p;":
        'true\n',
    F'class C {{ m() {{ {_REPORTS_THE_MODE_IT_STANDS_IN} }} }}\nnew C().m();':
        'true\n',
    F'class C {{ static {{ {_REPORTS_THE_MODE_IT_STANDS_IN} }} }}':
        'true\n',
    F'class C {{ p = (function () {{ {_REPORTS_THE_MODE_IT_STANDS_IN} }})(); }}\nnew C();':
        'true\n',
    F"function f() {{ 'use strict'; {_REPORTS_THE_MODE_IT_STANDS_IN} }}\n"
    F'function g() {{ {_REPORTS_THE_MODE_IT_STANDS_IN} }}\nf();\ng();':
        'true\nfalse\n',
    F"{_REPORTS_THE_MODE_IT_STANDS_IN}\n"
    F"(function () {{ 'use strict'; {_REPORTS_THE_MODE_IT_STANDS_IN} }})();":
        'false\ntrue\n',
    F"switch (1) {{ case 1: 'use strict'; {_REPORTS_THE_MODE_IT_STANDS_IN} }}":
        'false\n',
    F"try {{ throw 1; }} catch (e) {{ 'use strict'; {_REPORTS_THE_MODE_IT_STANDS_IN} }}":
        'false\n',
    F"for (var i = 0; i < 1; i++) {{ 'use strict'; {_REPORTS_THE_MODE_IT_STANDS_IN} }}":
        'false\n',
    F"L: {{ 'use strict'; {_REPORTS_THE_MODE_IT_STANDS_IN} }}":
        'false\n',
    F"console.log('x');\n'use strict';\n{_REPORTS_THE_MODE_IT_STANDS_IN}":
        'x\nfalse\n',
    F"'note';\n'use strict';\n{_REPORTS_THE_MODE_IT_STANDS_IN}":
        'true\n',
    "function f(a) { 'use strict'; a = 2; return arguments[0]; }\nconsole.log(f(1));":
        '1\n',
    "'use strict';\nvar s = ['con', 'sole'];\nconsole.log(s[0] + s[1]);\n"
    + _REPORTS_THE_MODE_IT_STANDS_IN:
        'console\ntrue\n',
}

A_READ_WHERE_NO_PROLOGUE_IS_READ = {
    "{ 'abc'[0]; }": (
        "{\n  'a';\n}",
        '',
    ),
    "switch (1) { case 1: 'abc'[0]; }": (
        "switch (1) {\n  case 1:\n    'a';\n}",
        '',
    ),
    "try { f(); } catch (e) { 'abc'[0]; }": (
        "try {\n  f();\n} catch (e) {\n  'a';\n}",
        inspect.cleandoc("""
            try {
              f();
            } catch (e) {}
        """),
    ),
    "L: { 'abc'[0]; }": (
        "L: {\n  'a';\n}",
        '',
    ),
    "function f() { { 'abc'[0]; } }": (
        "function f() {\n  {\n    'a';\n  }\n}",
        'function f() {}',
    ),
}

A_READ_WHERE_A_PROLOGUE_IS_READ = {
    "'abc'[0];": (
        "'abc'[0];",
        '',
    ),
    "function f() { 'abc'[0]; }": (
        "function f() {\n  'abc'[0];\n}",
        'function f() {}',
    ),
}


def _a_function_whose_body_opens_with(head: str, parameters: str, call: str, read: str) -> str:
    return (
        F'function f({parameters}) {{ {head} return {read}; }}\n'
        F'console.log({call});\n'
    )


_A_PARAMETER_LIST_NO_DIRECTIVE_MAY_STAND_UNDER = {
    'a = 1' : ('f()', 'a', '1\n'),
    '...a'  : ('f(1, 2)', 'a.length', '2\n'),
    '{a}'   : ('f({a: 5})', 'a', '5\n'),
}

A_FUNCTION_WHOSE_PARAMETER_LIST_FORBIDS_A_DIRECTIVE = {
    _a_function_whose_body_opens_with(
        "atob('YQ=='); 'use strict';", parameters, call, read): prints
    for parameters, (call, read, prints) in _A_PARAMETER_LIST_NO_DIRECTIVE_MAY_STAND_UNDER.items()
}

A_FUNCTION_WHOSE_BODY_OPENS_WITH_A_FOLD_TO_THE_DIRECTIVE = {
    _a_function_whose_body_opens_with(head, parameters, call, read): prints
    for parameters, (call, read, prints) in _A_PARAMETER_LIST_NO_DIRECTIVE_MAY_STAND_UNDER.items()
    for head in SPELLINGS_A_FOLD_WRITES_AS_THE_DIRECTIVE
}

A_HEAD_A_MOVE_PROMOTES_THE_STATEMENT_BELOW = [
    "if (1) { 'use strict'; }",
    "var dead = 1; 'use strict';",
]

A_FUNCTION_A_MOVE_WOULD_WRITE_A_DIRECTIVE_INTO = {
    _a_function_whose_body_opens_with(head, parameters, call, read): prints
    for parameters, (call, read, prints) in _A_PARAMETER_LIST_NO_DIRECTIVE_MAY_STAND_UNDER.items()
    for head in A_HEAD_A_MOVE_PROMOTES_THE_STATEMENT_BELOW
}


def _a_strict_body_holding(statements: str, installs: str = '') -> str:
    body = (
        F'function f(a) {{ {THE_DIRECTIVE}{statements}'
        F' return {_THE_MODE_IT_STANDS_IN}; }}\n'
        'console.log(f(1));\n'
    )
    return F'{installs}\n{body}' if installs else body


def _a_strict_script_holding(statements: str) -> str:
    return F"{THE_DIRECTIVE}{statements}\n{_REPORTS_THE_MODE_IT_STANDS_IN}\n"


A_BODY_WHOSE_DIRECTIVE_STANDS_BESIDE_A_BINDING_NOTHING_READS = {
    _a_strict_body_holding('q = a;', 'var q;'): 'true\n',
    _a_strict_script_holding('var q;\nq = 1;'): 'true\n',
    _a_strict_body_holding('var NS = {}; NS.p = 1; console.log(NS.p);'): '1\ntrue\n',
    _a_strict_script_holding('var NS = {};\nNS.p = 1;\nconsole.log(NS.p);'): '1\ntrue\n',
}


def _an_accessor_returning_a_strict_function(body: str, run: str) -> str:
    return (
        'var acc = (function () {\n'
        "  var t = ['a', 'b'];\n"
        F"  return function (i) {{ 'use strict'; {body} }};\n"
        '})();\n'
        F'{run}\n'
    )


AN_ACCESSOR_WHOSE_RETURNED_BODY_OPENS_WITH_A_DIRECTIVE = {
    _an_accessor_returning_a_strict_function(
        F"return t[i] + ({_THE_MODE_IT_STANDS_IN} ? 'S' : 'L');",
        'console.log(acc(1));',
    ): 'bS\n',
    _an_accessor_returning_a_strict_function(
        'undeclared = i; return t[i] + undeclared;',
        'try { console.log(acc(1)); } catch (e) { console.log(e.constructor.name); }',
    ): 'ReferenceError\n',
    _an_accessor_returning_a_strict_function(
        F"'note'; return t[i] + ({_THE_MODE_IT_STANDS_IN} ? 'S' : 'L');",
        'console.log(acc(1));',
    ): 'bS\n',
}

A_BODY_REPORTING_THE_MODE_ITS_PROLOGUE_DECIDES = {
    'a script'               : ('{head} console.log({mode});', 'false\n'),
    'a function declaration' : (
        'function f() {{ {head} return {mode}; }} console.log(f());', 'false\n'),
    'a function expression'  : (
        'var f = function () {{ {head} return {mode}; }}; console.log(f());', 'false\n'),
    'an arrow with a block'  : (
        'var f = () => {{ {head} return {mode}; }}; console.log(f());', 'false\n'),
    'a method'               : (
        'var o = {{ m() {{ {head} return {mode}; }} }}; console.log(o.m());', 'false\n'),
    'a getter'               : (
        'var o = {{ get g() {{ {head} return {mode}; }} }}; console.log(o.g);', 'false\n'),
    'a setter'               : (
        'var o = {{ set s(v) {{ {head} console.log({mode}); }} }}; o.s = 1;', 'false\n'),
    'a generator'            : (
        'function* g() {{ {head} yield {mode}; }} console.log(g().next().value);', 'false\n'),
    'an async function'      : (
        'async function h() {{ {head} return {mode}; }}'
        ' h().then(function (v) {{ console.log(v); }});', 'false\n'),
    'a class method'         : (
        'class C {{ m() {{ {head} console.log({mode}); }} }} new C().m();', 'true\n'),
    'a class static block'   : (
        'class C {{ static {{ {head} console.log({mode}); }} }}', 'true\n'),
}

A_ROUTE_A_STRING_ARRIVES_AT_THE_HEAD_BY = {
    'a fold'      : "'use ' + 'strict';",
    'a decode'    : "atob('dXNlIHN0cmljdA==');",
    'an inlining' : "var m = 'use strict'; m;",
    'a removal'   : "var dead = 1; 'use strict';",
}

A_HEAD_DECLARING_A_MODE = {
    "'use ' + 'strict';"                   : False,
    "var dead = 1; 'use strict';"          : False,
    "'use ' + 'strict'; 'use strict';"     : False,
    "'use strict';"                        : True,
    "'use strict'; var dead = 1; 'other';" : True,
    "var dead = 1; 'other';"               : False,
}


def _refused(programs: Sequence[str]) -> list[bool]:
    """
    Whether Node refuses to read each of *programs* as a script.
    """
    return [
        value == NOT_A_PROGRAM
        for value in completion_values(programs, JsEvaluation.SCRIPT)
    ]


def _without_the_directive(source: str) -> str:
    return source.replace(THE_DIRECTIVE, '', 1)


def _the_directive_statement(root: Node) -> JsExpressionStatement:
    statement, = (
        node for node in root.walk()
        if isinstance(node, JsExpressionStatement)
        and isinstance(node.expression, JsStringLiteral)
        and node.expression.body == 'use strict'
    )
    return statement


def _the_binding_named_eval(root: Node) -> JsIdentifier:
    name, = (
        node for node in root.walk()
        if isinstance(node, JsIdentifier) and node.name == 'eval'
    )
    return name


def _the_strict_error(root: Node) -> JsNumericLiteral | JsUnaryExpression:
    error, = (
        node for node in root.walk()
        if isinstance(node, JsNumericLiteral) and node.raw == '010'
        or isinstance(node, JsUnaryExpression) and node.operator == 'delete'
    )
    return error


def _the_computed_string_statement(root: Node) -> JsExpressionStatement:
    statement, = (
        node for node in root.walk()
        if isinstance(node, JsExpressionStatement)
        and any(
            isinstance(inner, JsStringLiteral) and inner.body == 'a'
            for inner in node.walk()
        )
    )
    return statement


def _the_function(
    root: Node,
) -> JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression:
    function, = (
        node for node in root.walk()
        if isinstance(
            node,
            (JsFunctionDeclaration, JsFunctionExpression, JsArrowFunctionExpression),
        )
    )
    return function


def _prologue_spellings(host: Node) -> list[str]:
    return [
        statement.expression.body
        for statement in directive_prologue(host)
        if isinstance(statement.expression, JsStringLiteral)
    ]


def _marked_spellings(script: JsScript) -> list[str]:
    return [
        statement.expression.body
        for statement in script.body
        if isinstance(statement, JsExpressionStatement)
        and statement.directive
        and isinstance(statement.expression, JsStringLiteral)
    ]


def _a_script_whose_directive_stands_below(head: str) -> str:
    return F"{head} 'use strict'; 010;"


def _a_function_body_whose_directive_stands_below(head: str) -> str:
    return F"function f() {{ {head} 'use strict'; 010; }}"


def _a_body_with_the_directive_at(index: int) -> str:
    statements = list(A_BODY_WRITTEN_AS)
    statements.insert(index, "'use strict';")
    return F'{" ".join(statements)} 010;'


def _deobfuscated(source: str) -> str:
    return source.encode('utf8') | djs(strict=True) | str


def _before_and_after(source: str) -> tuple[tuple[str, str | None], tuple[str, str | None]]:
    return behavior(source), behavior(deobfuscate_source(source))


def _before_and_after_as_a_script(
    source: str,
) -> tuple[tuple[str, str | None], tuple[str, str | None]]:
    return host_behavior(source), host_behavior(deobfuscate_source(source))


def _each_program_still_prints(
    programs: dict[str, str],
) -> dict[str, tuple[tuple[str, str | None], tuple[str, str | None]]]:
    return {
        source: ((prints, None), (prints, None))
        for source, prints in programs.items()
    }


def _a_body_opened_by(head: str, template: str) -> str:
    return template.format(head=head, mode=_THE_MODE_IT_STANDS_IN)


def _a_function_body_opening_with_and_calling_g(head: str) -> str:
    return inspect.cleandoc(F"""
        function f(a) {{ {head} g(a); }}
        f(1);
    """)


def _a_function_body_opening_with_and_declaring_what_g_answers(
    head: str,
    parameters: str = 'a',
) -> str:
    return inspect.cleandoc(F"""
        function f({parameters}) {{ {head} var b = g(a); }}
        f(1);
    """)


def _the_call_of_g(root: Node) -> JsCallExpression:
    call, = (
        node for node in root.walk()
        if isinstance(node, JsCallExpression)
        and isinstance(node.callee, JsIdentifier)
        and node.callee.name == 'g'
    )
    return call


def _the_mode_the_deobfuscation_calls_g_in(source: str) -> bool:
    return strict_mode_at(_the_call_of_g(JsParser(_deobfuscated(source)).parse()))


def _strings_standing_as_statements(root: Node) -> list[str]:
    literals = (
        strip_parens(node.expression)
        for node in root.walk()
        if isinstance(node, JsExpressionStatement)
    )
    return [literal.body for literal in literals if isinstance(literal, JsStringLiteral)]


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestWhichBodiesReadADirectivePrologue(TestBase):

    def test_a_directive_at_the_head_of_a_prologue_host_makes_the_code_below_it_strict(self):
        sources = list(A_BODY_A_PROLOGUE_OPENS.values())
        self.assertEqual(_refused(sources), [True] * len(sources))

    def test_the_same_body_without_the_directive_is_sloppy(self):
        sources = [_without_the_directive(s) for s in A_BODY_A_PROLOGUE_OPENS.values()]
        self.assertEqual(_refused(sources), [False] * len(sources))

    def test_a_directive_at_the_head_of_any_other_statement_list_changes_no_mode(self):
        sources = list(A_BODY_NO_PROLOGUE_OPENS.values())
        self.assertEqual(_refused(sources), [False] * len(sources))

    def test_those_bodies_are_sloppy_without_the_directive_too(self):
        sources = [_without_the_directive(s) for s in A_BODY_NO_PROLOGUE_OPENS.values()]
        self.assertEqual(_refused(sources), [False] * len(sources))

    def test_a_class_static_block_is_strict_whatever_stands_at_its_head(self):
        self.assertEqual(
            _refused([A_CLASS_STATIC_BLOCK, _without_the_directive(A_CLASS_STATIC_BLOCK)]),
            [True, True],
        )


class TestIsPrologueHostAnswersForTheBodiesTheEngineReadsOneIn(TestBase):

    def _hosts(self, sources: Sequence[str]) -> list[bool]:
        return [
            is_prologue_host(_the_directive_statement(JsParser(source).parse()).parent)
            for source in sources
        ]

    def test_a_body_the_engine_compiled_strict_holds_a_prologue(self):
        sources = list(A_BODY_A_PROLOGUE_OPENS.values()) + [A_CLASS_STATIC_BLOCK]
        self.assertEqual(self._hosts(sources), [True] * len(sources))

    def test_a_body_the_engine_left_sloppy_holds_none(self):
        sources = list(A_BODY_NO_PROLOGUE_OPENS.values())
        self.assertEqual(self._hosts(sources), [False] * len(sources))


class TestStrictModeAtAnswersTheModeTheEngineCompiled(TestBase):

    def _modes(self, sources: Sequence[str]) -> list[bool]:
        return [
            strict_mode_at(_the_strict_error(JsParser(source).parse()))
            for source in sources
        ]

    def test_the_strict_error_below_a_directive_a_body_reads_stands_in_strict_code(self):
        sources = list(A_BODY_A_PROLOGUE_OPENS.values()) + [A_CLASS_STATIC_BLOCK]
        self.assertEqual(self._modes(sources), [True] * len(sources))

    def test_the_strict_error_below_a_directive_no_body_reads_stands_in_sloppy_code(self):
        sources = list(A_BODY_NO_PROLOGUE_OPENS.values())
        self.assertEqual(self._modes(sources), [False] * len(sources))

    def test_a_position_a_strict_body_encloses_inherits_the_mode_of_that_body(self):
        rows = A_STRICT_ERROR_STANDING_IN
        self.assertEqual(
            self._modes([source for source, _ in rows.values()]),
            [strict for _, strict in rows.values()],
        )

    def _eval_modes(self, sources: Sequence[str]) -> list[bool]:
        return [
            strict_mode_at(_the_binding_named_eval(JsParser(source).parse()))
            for source in sources
        ]

    def test_the_name_and_the_parameters_of_a_function_stand_in_the_mode_of_its_body(self):
        sources = list(A_BINDING_THE_DIRECTIVE_GOVERNS.values())
        self.assertEqual(self._eval_modes(sources), [True] * len(sources))

    def test_a_binding_the_directive_does_not_govern_stands_in_sloppy_code(self):
        sources = list(A_BINDING_OUTSIDE_WHAT_IT_GOVERNS.values())
        self.assertEqual(self._eval_modes(sources), [False] * len(sources))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestModeIsInheritedByEverythingAStrictBodyEncloses(TestBase):

    def test_node_compiles_each_position_in_the_mode_the_corpus_records(self):
        rows = A_STRICT_ERROR_STANDING_IN
        self.assertEqual(
            _refused([source for source, _ in rows.values()]),
            [strict for _, strict in rows.values()],
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestWhatAFunctionBodysDirectiveGovernsBesidesThatBody(TestBase):

    def test_node_refuses_the_name_bound_in_the_code_the_directive_governs(self):
        sources = list(A_BINDING_THE_DIRECTIVE_GOVERNS.values())
        self.assertEqual(_refused(sources), [True] * len(sources))

    def test_node_reads_the_same_name_bound_anywhere_else(self):
        sources = list(A_BINDING_OUTSIDE_WHAT_IT_GOVERNS.values())
        self.assertEqual(_refused(sources), [False] * len(sources))

    def test_it_is_the_directive_and_not_the_name_that_costs_the_program(self):
        sources = [
            _without_the_directive(source)
            for source in A_BINDING_THE_DIRECTIVE_GOVERNS.values()
        ]
        self.assertEqual(_refused(sources), [False] * len(sources))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestHowFarADirectivePrologueReaches(TestBase):

    def test_a_directive_is_read_below_string_literal_statements_and_below_nothing_else(self):
        rows = A_STATEMENT_ABOVE_THE_DIRECTIVE
        self.assertEqual(
            _refused([_a_script_whose_directive_stands_below(head) for head in rows]),
            list(rows.values()),
        )

    def test_a_function_body_reads_its_prologue_the_same_way_a_script_does(self):
        rows = A_STATEMENT_ABOVE_THE_DIRECTIVE
        self.assertEqual(
            _refused([_a_function_body_whose_directive_stands_below(head) for head in rows]),
            list(rows.values()),
        )

    def test_a_directive_stands_anywhere_from_the_head_up_to_the_end_of_the_prologue(self):
        indices = range(len(A_BODY_WRITTEN_AS) + 1)
        self.assertEqual(
            _refused([_a_body_with_the_directive_at(index) for index in indices]),
            [True, True, True, False, False],
        )


class TestTheDirectivePrologueTheToolReads(TestBase):

    def test_declares_use_strict_answers_what_the_engine_compiled(self):
        rows = A_STATEMENT_ABOVE_THE_DIRECTIVE
        self.assertEqual(
            [
                declares_use_strict(JsParser(_a_script_whose_directive_stands_below(head)).parse())
                for head in rows
            ],
            list(rows.values()),
        )

    def test_the_prologue_is_the_run_of_string_literal_statements_a_body_opens_with(self):
        script = JsParser(F'{" ".join(A_BODY_WRITTEN_AS)} 010;').parse()
        self.assertEqual(_prologue_spellings(script), ['alpha', 'beta'])

    def test_a_body_that_opens_with_no_string_literal_has_an_empty_prologue(self):
        script = JsParser("0; 'alpha'; 'beta';").parse()
        self.assertEqual(_prologue_spellings(script), [])


class TestWhichStatementsTheParserRecordsAsWrittenIntoAPrologue(TestBase):

    def _marked(self, sources: Sequence[str]) -> list[bool]:
        return [
            _the_directive_statement(JsParser(source).parse()).directive
            for source in sources
        ]

    def test_the_directive_of_a_body_the_engine_compiled_strict_is_marked(self):
        sources = list(A_BODY_A_PROLOGUE_OPENS.values()) + [A_CLASS_STATIC_BLOCK]
        self.assertEqual(self._marked(sources), [True] * len(sources))

    def test_the_same_statement_in_a_body_the_engine_left_sloppy_is_not(self):
        sources = list(A_BODY_NO_PROLOGUE_OPENS.values())
        self.assertEqual(self._marked(sources), [False] * len(sources))

    def test_the_mark_is_on_the_run_of_string_literals_a_body_opens_with(self):
        script = JsParser(F'{" ".join(A_BODY_WRITTEN_AS)} 010;').parse()
        self.assertEqual(_marked_spellings(script), ['alpha', 'beta'])

    def test_a_body_opening_with_no_string_literal_marks_nothing(self):
        script = JsParser("0; 'alpha'; 'beta';").parse()
        self.assertEqual(_marked_spellings(script), [])


class TestWhichStatementIsTheOneThatDeclaresTheMode(TestBase):

    def _declares(self, sources: Sequence[str]) -> list[bool]:
        return [
            is_use_strict_directive(_the_directive_statement(JsParser(source).parse()))
            for source in sources
        ]

    def test_it_holds_for_the_directive_of_every_body_the_engine_compiled_strict(self):
        sources = list(A_BODY_A_PROLOGUE_OPENS.values()) + [A_CLASS_STATIC_BLOCK]
        self.assertEqual(self._declares(sources), [True] * len(sources))

    def test_it_holds_for_no_statement_of_a_body_the_engine_left_sloppy(self):
        sources = list(A_BODY_NO_PROLOGUE_OPENS.values())
        self.assertEqual(self._declares(sources), [False] * len(sources))

    def test_it_holds_for_no_string_that_declares_another_mode(self):
        sources = [
            "'use loose'; 010;",
            "function f() { 'use loose'; 010; }",
            "'use loose'; 'use strict';",
        ]
        answers = [
            [
                is_use_strict_directive(statement)
                for statement in JsParser(source).parse().walk()
                if isinstance(statement, JsExpressionStatement)
                and isinstance(statement.expression, JsStringLiteral)
                and statement.expression.body == 'use loose'
            ]
            for source in sources
        ]
        self.assertEqual(answers, [[False], [False], [False]])


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestWhichStatementsWouldJoinADirectivePrologue(TestBase):

    def test_a_statement_that_is_no_string_literal_hands_no_directive_position_away(self):
        sources = [
            template.format(stmt=A_COMPUTED_STRING)
            for template, _ in A_STATEMENT_STANDING_AT.values()
        ]
        self.assertEqual(_refused(sources), [False] * len(sources))

    def test_respelling_it_as_a_string_literal_extends_the_prologue_over_what_follows(self):
        rows = A_STATEMENT_STANDING_AT
        self.assertEqual(
            _refused([template.format(stmt=A_PLAIN_STRING) for template, _ in rows.values()]),
            [joins for _, joins in rows.values()],
        )

    def test_joins_directive_prologue_answers_what_the_respelling_costs(self):
        rows = A_STATEMENT_STANDING_AT
        self.assertEqual(
            [
                joins_directive_prologue(
                    _the_computed_string_statement(
                        JsParser(template.format(stmt=A_COMPUTED_STRING)).parse()))
                for template, _ in rows.values()
            ],
            [joins for _, joins in rows.values()],
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestWhichParameterListsADirectiveMayStandUnder(TestBase):

    def test_node_refuses_a_directive_under_every_list_that_is_not_simple(self):
        for shape, template in A_FUNCTION_WRITTEN_AS.items():
            sources = [
                template.format(params=params, body="'use strict';")
                for params in A_PARAMETER_LIST
            ]
            with self.subTest(shape=shape):
                self.assertEqual(
                    _refused(sources),
                    [not simple for simple in A_PARAMETER_LIST.values()],
                )

    def test_node_reads_every_one_of_those_lists_with_an_empty_body(self):
        for shape, template in A_FUNCTION_WRITTEN_AS.items():
            sources = [
                template.format(params=params, body='')
                for params in A_PARAMETER_LIST
            ]
            with self.subTest(shape=shape):
                self.assertEqual(_refused(sources), [False] * len(sources))


class TestHasSimpleParametersAnswersWhereADirectiveIsPermitted(TestBase):

    def test_a_list_is_simple_exactly_where_the_engine_permits_a_directive_under_it(self):
        for shape, template in A_FUNCTION_WRITTEN_AS.items():
            answers = [
                has_simple_parameters(
                    _the_function(JsParser(template.format(params=params, body='')).parse()))
                for params in A_PARAMETER_LIST
            ]
            with self.subTest(shape=shape):
                self.assertEqual(answers, list(A_PARAMETER_LIST.values()))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestDeobfuscationLeavesEveryModeWhereItWas(TestBase):

    def test_node_prints_what_the_corpus_records_for_each_program(self):
        rows = A_PROGRAM_REPORTING_ITS_MODE
        self.assertEqual(
            {source: host_behavior(source) for source in rows},
            {source: (printed, None) for source, printed in rows.items()},
        )

    def test_the_deobfuscation_of_each_program_prints_the_same(self):
        rows = A_PROGRAM_REPORTING_ITS_MODE
        self.assertEqual(
            {source: host_behavior(_deobfuscated(source)) for source in rows},
            {source: (printed, None) for source, printed in rows.items()},
        )


class TestAFoldDeclinesOnlyWhereADirectiveCouldBeRead(TestBase):

    def test_a_read_in_a_body_that_opens_no_prologue_is_folded_or_removed(self):
        for source, (folded, removed) in A_READ_WHERE_NO_PROLOGUE_IS_READ.items():
            with self.subTest(source=source):
                self.assertIn(_deobfuscated(source), (folded, removed))

    def test_a_read_that_would_join_a_prologue_is_left_standing_or_removed(self):
        for source, (standing, removed) in A_READ_WHERE_A_PROLOGUE_IS_READ.items():
            with self.subTest(source=source):
                self.assertIn(_deobfuscated(source), (standing, removed))

    @opportunity
    def test_a_read_whose_string_nothing_uses_is_removed_wherever_it_stands(self):
        rows = {**A_READ_WHERE_NO_PROLOGUE_IS_READ, **A_READ_WHERE_A_PROLOGUE_IS_READ}
        self.assertEqual(
            {source: _deobfuscated(source) for source in rows},
            {source: removed for source, (_, removed) in rows.items()},
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFoldWritesNoDirectiveWhereNoneWasWritten(TestBase):

    def test_a_statement_that_only_denotes_the_text_leaves_the_script_sloppy(self):
        sloppy = ('false\n', None)
        spellings = SPELLINGS_A_FOLD_WRITES_AS_THE_DIRECTIVE
        self.assertEqual(
            [_before_and_after(a_script_opening_with(head)) for head in spellings],
            [(sloppy, sloppy)] * len(spellings),
        )

    def test_a_statement_that_only_denotes_the_text_leaves_the_function_body_sloppy(self):
        sloppy = ('false\n', None)
        spellings = SPELLINGS_A_FOLD_WRITES_AS_THE_DIRECTIVE
        self.assertEqual(
            [_before_and_after(a_function_body_opening_with(head)) for head in spellings],
            [(sloppy, sloppy)] * len(spellings),
        )

    def test_a_file_that_holds_an_octal_literal_still_parses(self):
        eight = ('8\n', None)
        spellings = SPELLINGS_A_FOLD_WRITES_AS_THE_DIRECTIVE
        self.assertEqual(
            [
                _before_and_after(a_file_holding_an_octal_literal_opening_with(head))
                for head in spellings
            ],
            [(eight, eight)] * len(spellings),
        )

    def test_a_statement_folded_to_a_plain_string_does_not_extend_the_prologue(self):
        sloppy = ('false\n', None)
        spellings = SPELLINGS_A_FOLD_WRITES_AS_A_PLAIN_STRING
        self.assertEqual(
            [_before_and_after(a_script_whose_directive_stands_below(head)) for head in spellings],
            [(sloppy, sloppy)] * len(spellings),
        )

    def test_a_fold_writes_no_prologue_into_a_function_that_can_hold_none(self):
        rows = A_FUNCTION_WHOSE_PARAMETER_LIST_FORBIDS_A_DIRECTIVE
        self.assertEqual(
            {source: _before_and_after(source) for source in rows},
            _each_program_still_prints(rows),
        )

    def test_a_fold_writes_no_directive_into_a_function_that_can_hold_none(self):
        rows = A_FUNCTION_WHOSE_BODY_OPENS_WITH_A_FOLD_TO_THE_DIRECTIVE
        self.assertEqual(
            {source: _before_and_after(source) for source in rows},
            _each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestMovingAStatementDoesNotChangeWhichStatementsAreDirectives(TestBase):

    def test_lifting_a_block_into_the_body_around_it_writes_no_directive(self):
        sloppy = ('false\n', None)
        sources = [
            a_script_opening_with("if (1) { 'use strict'; }"),
            a_function_body_opening_with("if (1) { 'use strict'; }"),
        ]
        self.assertEqual(
            [_before_and_after_as_a_script(source) for source in sources],
            [(sloppy, sloppy)] * len(sources),
        )

    def test_dropping_a_statement_writes_no_directive_below_it(self):
        sloppy = ('false\n', None)
        sources = [
            a_script_opening_with("var dead = 1; 'use strict';"),
            a_function_body_opening_with("var dead = 1; 'use strict';"),
        ]
        self.assertEqual(
            [_before_and_after_as_a_script(source) for source in sources],
            [(sloppy, sloppy)] * len(sources),
        )

    def test_writing_a_declaration_into_a_body_leaves_its_directive_first(self):
        rows = AN_ACCESSOR_WHOSE_RETURNED_BODY_OPENS_WITH_A_DIRECTIVE
        self.assertEqual(
            {source: _before_and_after_as_a_script(source) for source in rows},
            _each_program_still_prints(rows),
        )

    def test_a_move_writes_no_directive_into_a_function_that_can_hold_none(self):
        rows = A_FUNCTION_A_MOVE_WOULD_WRITE_A_DIRECTIVE_INTO
        self.assertEqual(
            {source: _before_and_after(source) for source in rows},
            _each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestADirectiveIsNotAStatementThatCanBeDiscarded(TestBase):

    def test_a_directive_survives_the_removal_of_a_binding_beside_it(self):
        rows = A_BODY_WHOSE_DIRECTIVE_STANDS_BESIDE_A_BINDING_NOTHING_READS
        self.assertEqual(
            {source: _before_and_after_as_a_script(source) for source in rows},
            _each_program_still_prints(rows),
        )

    def test_the_same_bodies_report_sloppy_once_the_directive_is_taken_out(self):
        rows = A_BODY_WHOSE_DIRECTIVE_STANDS_BESIDE_A_BINDING_NOTHING_READS
        sloppy = {
            _without_the_directive(source): prints.replace('true', 'false')
            for source, prints in rows.items()
        }
        self.assertEqual(
            {source: _before_and_after_as_a_script(source) for source in sloppy},
            _each_program_still_prints(sloppy),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAStringPromotedIntoAPrologueGovernsNothing(TestBase):

    def _programs(self) -> dict[str, str]:
        return {
            _a_body_opened_by(head, template): prints
            for template, prints in A_BODY_REPORTING_THE_MODE_ITS_PROLOGUE_DECIDES.values()
            for head in A_ROUTE_A_STRING_ARRIVES_AT_THE_HEAD_BY.values()
        }

    def test_node_prints_what_the_corpus_records_for_each_body(self):
        rows = self._programs()
        self.assertEqual(
            {source: host_behavior(source) for source in rows},
            {source: (prints, None) for source, prints in rows.items()},
        )

    def test_the_deobfuscation_of_each_body_prints_the_same(self):
        rows = self._programs()
        self.assertEqual(
            {source: host_behavior(deobfuscate_source(source)) for source in rows},
            {source: (prints, None) for source, prints in rows.items()},
        )


class TestThePrinterWritesOnlyADirectiveTheSourceWrote(TestBase):

    @staticmethod
    def _deobfuscation_of(head: str) -> Node:
        return JsParser(_deobfuscated(_a_function_body_opening_with_and_calling_g(head))).parse()

    def test_the_call_below_each_head_stands_in_the_mode_the_source_gave_it(self):
        rows = A_HEAD_DECLARING_A_MODE
        self.assertEqual(
            {head: strict_mode_at(_the_call_of_g(self._deobfuscation_of(head))) for head in rows},
            dict(rows),
        )

    def test_no_string_statement_survives_but_the_directive_the_source_wrote(self):
        rows = A_HEAD_DECLARING_A_MODE
        self.assertEqual(
            {head: _strings_standing_as_statements(self._deobfuscation_of(head)) for head in rows},
            {head: ['use strict'] if strict else [] for head, strict in rows.items()},
        )

    def test_a_string_promoted_above_a_declaration_changes_no_mode(self):
        rows = {
            _a_function_body_opening_with_and_declaring_what_g_answers(head): strict
            for head, strict in A_HEAD_DECLARING_A_MODE.items()
        }
        self.assertEqual(
            {source: _the_mode_the_deobfuscation_calls_g_in(source) for source in rows},
            rows,
        )

    def test_a_string_promoted_into_a_function_that_can_hold_none_writes_no_directive(self):
        sources = [
            _a_function_body_opening_with_and_declaring_what_g_answers(head, parameters)
            for parameters in _A_PARAMETER_LIST_NO_DIRECTIVE_MAY_STAND_UNDER
            for head, strict in A_HEAD_DECLARING_A_MODE.items()
            if not strict
        ]
        self.assertEqual(
            {source: _the_mode_the_deobfuscation_calls_g_in(source) for source in sources},
            dict.fromkeys(sources, False),
        )
